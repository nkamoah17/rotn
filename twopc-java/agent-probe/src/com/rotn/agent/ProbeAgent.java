package com.rot.n.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

/** W2 production probe agent.
 *
 *  Instruments the single trace choke point {@code Bus.record(TraceEvent)}
 *  (internal name com/rot/n/twopc/Bus) by injecting on the NORMAL path,
 *  just before the exit jump (or, for a plain tail, just before the final
 *  RETURN):
 *
 *      ALOAD 0
 *      ALOAD 1
 *      INVOKESTATIC com/rot/n/probe/Probe.record(Object,TraceEvent)V
 *
 *  The javac layout of a synchronized method is
 *      ...body...; aload_2; monitorexit; goto L_end;  <handler: ...; athrow>; L_end: return
 *  so "before the final RETURN" sits on the handler fall-through path --
 *  unreachable, and that is exactly what the first cut did. The correct
 *  anchor is the `goto` that skips the handler tail: the probe then fires
 *  on the live path, with an empty stack, after the seq assignment and
 *  after the monitor release, and no new branch target is created. The
 *  call is stack-neutral (void, args popped) and Probe.record swallows all
 *  Throwables, so it never disrupts the target. We still rebuild with
 *  COMPUTE_FRAMES so the ClassWriter recomputes all stack map frames (and
 *  maxStack) for the shifted offsets; all referenced types are resolvable
 *  by the system classloader, so getCommonSuperClass succeeds.
 *
 *  Re-transform safety: if the classfile already carries our marker
 *  (constant pool reference to the Probe class) the transformer returns
 *  null, so double instrumentation is impossible.
 */
public final class ProbeAgent {
    private static final String TARGET_CLASS = "com/rot/n/twopc/Bus";
    private static final String TARGET_METHOD = "record";
    private static final String TARGET_DESC = "(Lcom/rot/n/twopc/TraceEvent;)V";
    private static final String PROBE_CLASS = "com/rot/n/probe/Probe";
    private static final String PROBE_METHOD = "record";
    private static final String PROBE_DESC = "(Ljava/lang/Object;Lcom/rot/n/twopc/TraceEvent;)V";
    private static final byte[] MARKER = "rotn/probe/Probe".getBytes();

    public static void premain(String agentArgs, Instrumentation inst) {
        // Probe lives on the app classpath (build/classes); the agent jar is
        // loaded by the same system classloader, so a direct static call
        // resolves. init() is idempotent and never throws.
        com.rot.n.probe.Probe.init();
        inst.addTransformer(new Transformer(), false);
        System.out.println("PROBE-AGENT premain ok (target "
                + TARGET_CLASS + "#" + TARGET_METHOD + TARGET_DESC + ")");
    }

    /** Attach-mode entry (W6). Registers the transformer; retransform of an
     *  already-loaded Bus is added by the W6 attach flow. */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        premain(agentArgs, inst);
    }

    private static final class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (!TARGET_CLASS.equals(className) || alreadyInstrumented(classfileBuffer)) {
                return null;
            }
            try {
                ClassNode cn = new ClassNode();
                new ClassReader(classfileBuffer).accept(cn, 0);
                MethodNode mn = null;
                for (MethodNode m : cn.methods) {
                    if (TARGET_METHOD.equals(m.name) && TARGET_DESC.equals(m.desc)) {
                        mn = m;
                        break;
                    }
                }
                if (mn == null) {
                    System.err.println("PROBE-AGENT: " + TARGET_METHOD + TARGET_DESC
                            + " not found in " + TARGET_CLASS + "; leaving uninstrumented");
                    return null;
                }
                AbstractInsnNode insertBefore = findInsertPoint(mn);
                if (insertBefore == null) {
                    System.err.println("PROBE-AGENT: no safe insertion point on "
                            + "the normal path of " + TARGET_METHOD + TARGET_DESC
                            + "; leaving uninstrumented");
                    return null;
                }
                // In this vendored ASM build InsnList.insert(at, insn) places
                // the node immediately AFTER `at` (verified empirically), so
                // to land the probe on the live path just before the anchor
                // we repeatedly insert after the anchor's current predecessor:
                //   ... monitorexit, LABEL, ALOAD 0, ALOAD 1, INVOKESTATIC, GOTO(anchor) ...
                // Re-fetching the predecessor each iteration keeps the final
                // order ALOAD 0, ALOAD 1, INVOKESTATIC.
                for (AbstractInsnNode insn : new AbstractInsnNode[] {
                        new VarInsnNode(Opcodes.ALOAD, 0),
                        new VarInsnNode(Opcodes.ALOAD, 1),
                        new MethodInsnNode(Opcodes.INVOKESTATIC,
                                PROBE_CLASS, PROBE_METHOD, PROBE_DESC) }) {
                    AbstractInsnNode prev = insertBefore.getPrevious();
                    if (prev == null) {
                        mn.instructions.add(insn);
                    } else {
                        mn.instructions.insert(prev, insn);
                    }
                }
                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
                cn.accept(cw);
                byte[] out = cw.toByteArray();
                System.out.println("PROBE-AGENT instrumented " + className);
                return out;
            } catch (Throwable t) {
                System.err.println("PROBE-AGENT transform FAILED for "
                        + className + ": " + t);
                return null;
            }
        }
    }

    /** Find the instruction to insert before, on the NORMAL path of the
     *  method. Walk forward from the entry, following unconditional GOTOs,
     *  until the terminal RETURN is reached; the anchor is the last code
     *  instruction on that path. For a javac `synchronized` method that
     *  anchor is the `goto` skipping the exception-handler tail, so the
     *  probe fires just after the monitor release -- on the live path, with
     *  an empty stack. Returns null (leave uninstrumented) when the normal
     *  path hits an ATHROW, when a conditional branch appears (ambiguous
     *  normal path), or when no terminal RETURN is found.
     *
     *  Node classification is by concrete class, not by the numeric
     *  getType() codes (which differ between ASM builds): a void
     *  `return` is a plain InsnNode, xRETURN/ATHROW-carrying nodes are
     *  handled by opcode, and GOTOs are JumpInsnNodes. */
    private static AbstractInsnNode findInsertPoint(MethodNode mn) {
        AbstractInsnNode cur = mn.instructions.getFirst();
        AbstractInsnNode anchor = null;
        int guard = 0;
        while (cur != null && ++guard < 100000) {
            if (cur instanceof MethodInsnNode) {
                int op = ((MethodInsnNode) cur).getOpcode();
                if (op == Opcodes.IRETURN || op == Opcodes.LRETURN
                        || op == Opcodes.FRETURN || op == Opcodes.DRETURN
                        || op == Opcodes.ARETURN) {
                    return anchor;
                }
                anchor = cur;
            } else if (cur.getClass() == InsnNode.class) {
                int op = ((InsnNode) cur).getOpcode();
                if (op == Opcodes.RETURN) {
                    return anchor;
                }
                if (op == Opcodes.ATHROW) {
                    // normal path entered the exception handler
                    return null;
                }
            } else if (cur instanceof JumpInsnNode) {
                JumpInsnNode jump = (JumpInsnNode) cur;
                if (jump.getOpcode() != Opcodes.GOTO) {
                    return null;
                }
                AbstractInsnNode target = labelTarget(mn, jump);
                if (target == null) {
                    return null;
                }
                anchor = cur;
                cur = target;
                continue;
            }
            cur = cur.getNext();
        }
        return null;
    }

    /** The instruction a GOTO jumps to: the node after the LABEL node that
     *  carries the jump's Label. */
    private static AbstractInsnNode labelTarget(MethodNode mn, JumpInsnNode jump) {
        if (jump.label == null) {
            return null;
        }
        for (AbstractInsnNode n : mn.instructions) {
            if (n instanceof LabelNode
                    && ((LabelNode) n).getLabel() == jump.label.getLabel()) {
                return n.getNext();
            }
        }
        return null;
    }

    /** True if the classfile already references the Probe class (constant
     *  pool marker) -- i.e. we already instrumented it. */
    private static boolean alreadyInstrumented(byte[] buf) {
        int limit = buf.length - MARKER.length;
        outer:
        for (int i = 0; i <= limit; i++) {
            for (int j = 0; j < MARKER.length; j++) {
                if (buf[i + j] != MARKER[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private ProbeAgent() {
    }
}
