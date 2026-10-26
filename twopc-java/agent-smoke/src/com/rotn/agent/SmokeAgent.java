package com.rot.n.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** W0 smoke agent: proves the -javaagent + ASM bytecode pipeline end to end.
 *
 *  Transform: in com/rotn/smoke/App, insert
 *      Probe.enter("App.<init>")
 *  at the start of the instance constructor. The inserted instruction is a
 *  stack-neutral static call (LDC + INVOKESTATIC), so it is safe to prepend.
 *
 *  This is deliberately minimal: the full W2 probe (global sequence ordering,
 *  Lamport headers, sync-point recording) builds on this same mechanism.
 */
public final class SmokeAgent {
    private static final String TARGET = "com/rot/n/smoke/App";
    private static final String PROBE = "com/rot/n/smoke/Probe";
    private static final String PROBE_SIG = "(Ljava/lang/String;)V";

    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new SmokeTransformer(), false);
        System.out.println("SMOKE-AGENT premain ok");
    }

    /** Also registered as the agent class so the same jar can attach to a
     *  running JVM later (used by the W6 cost benchmark). */
    public static void agentmain(String args, Instrumentation inst) {
        premain(args, inst);
    }

    private static final class SmokeTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (!TARGET.equals(className)) {
                return null;
            }
            try {
                ClassReader reader = new ClassReader(classfileBuffer);
                ClassWriter writer = new ClassWriter(reader, 0);
                reader.accept(new Instrumentor(writer), 0);
                return writer.toByteArray();
            } catch (Throwable t) {
                // Never break the target on a transform error: fall back to the
                // original bytes and report on stderr for the test harness.
                System.err.println("SMOKE-AGENT transform FAILED for " + className + ": " + t);
                t.printStackTrace();
                return null;
            }
        }

        private static final class Instrumentor extends ClassVisitor {
            Instrumentor(ClassVisitor cv) {
                super(Opcodes.ASM8, cv);
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                              String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("<init>".equals(name) && (access & Opcodes.ACC_STATIC) == 0) {
                    return new MethodVisitor(Opcodes.ASM8, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            super.visitLdcInsn("App.<init>");
                            super.visitMethodInsn(Opcodes.INVOKESTATIC, PROBE, "enter",
                                    PROBE_SIG, false);
                        }
                    };
                }
                return mv;
            }
        }
    }

    private SmokeAgent() {
    }
}
