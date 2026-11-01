import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

/** Apply the agent's exact insertion sequence to Bus.record and dump the
 *  resulting instruction list, both in the ClassNode and after a
 *  COMPUTE_FRAMES rewrite. */
public final class TransformDump {
    public static void main(String[] args) throws Exception {
        byte[] in = read(args[0]);
        ClassNode cn = new ClassNode();
        new ClassReader(in).accept(cn, 0);
        MethodNode mn = find(cn, "record");
        AbstractInsnNode anchor = null;
        for (AbstractInsnNode n : mn.instructions) {
            if (n instanceof JumpInsnNode && ((JumpInsnNode) n).getOpcode() == Opcodes.GOTO) {
                anchor = n;
                break;
            }
        }
        if (anchor == null) {
            throw new IllegalStateException("no goto found");
        }
        // corrected semantics: insert-before = insert-after(predecessor),
        // re-fetching the predecessor each iteration
        AbstractInsnNode[] seq = new AbstractInsnNode[] {
                new VarInsnNode(Opcodes.ALOAD, 0),
                new VarInsnNode(Opcodes.ALOAD, 1),
                new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "com/rot/n/probe/Probe", "record",
                        "(Ljava/lang/Object;Lcom/rot/n/twopc/TraceEvent;)V")};
        for (AbstractInsnNode insn : seq) {
            AbstractInsnNode prev = anchor.getPrevious();
            if (prev == null) {
                mn.instructions.add(insn);
            } else {
                mn.instructions.insert(prev, insn);
            }
        }
        System.out.println("--- ClassNode after agent-order inserts ---");
        dump(mn, anchor);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cn.accept(cw);
        byte[] out = cw.toByteArray();
        System.out.println("--- after COMPUTE_FRAMES rewrite ---");
        ClassNode cn2 = new ClassNode();
        new ClassReader(out).accept(cn2, 0);
        dump(find(cn2, "record"), null);
    }

    private static MethodNode find(ClassNode cn, String name) {
        for (MethodNode m : cn.methods) {
            if (name.equals(m.name)) {
                return m;
            }
        }
        throw new IllegalStateException(name + " not found");
    }

    private static void dump(MethodNode mn, AbstractInsnNode anchor) {
        java.util.Map<org.objectweb.asm.tree.LabelNode, Integer> labelAt =
                new java.util.IdentityHashMap<org.objectweb.asm.tree.LabelNode, Integer>();
        int idx = 0;
        for (AbstractInsnNode n : mn.instructions) {
            if (n instanceof org.objectweb.asm.tree.LabelNode) {
                labelAt.put((org.objectweb.asm.tree.LabelNode) n, idx);
            }
            idx++;
        }
        idx = 0;
        for (AbstractInsnNode n : mn.instructions) {
            String extra = "";
            if (n instanceof JumpInsnNode) {
                Integer li = labelAt.get(((JumpInsnNode) n).label);
                extra = " ->label@" + li;
            }
            if (n instanceof org.objectweb.asm.tree.MethodInsnNode) {
                org.objectweb.asm.tree.MethodInsnNode mi =
                        (org.objectweb.asm.tree.MethodInsnNode) n;
                extra += " " + mi.owner + "#" + mi.name + mi.desc;
            }
            if (n instanceof org.objectweb.asm.tree.FieldInsnNode) {
                org.objectweb.asm.tree.FieldInsnNode fi =
                        (org.objectweb.asm.tree.FieldInsnNode) n;
                extra += " " + fi.owner + "#" + fi.name;
            }
            if (n instanceof VarInsnNode) {
                extra += " slot=" + ((VarInsnNode) n).var;
            }
            if (n == anchor) {
                extra += "  <== ANCHOR (goto)";
            }
            System.out.println(String.format("%2d %-28s op=%d%s", idx++,
                    n.getClass().getSimpleName(), n.getOpcode(), extra));
        }
    }

    private static byte[] read(String path) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        java.io.InputStream is = new java.io.FileInputStream(path);
        try {
            byte[] b = new byte[8192];
            int r;
            while ((r = is.read(b)) > 0) {
                bos.write(b, 0, r);
            }
        } finally {
            is.close();
        }
        return bos.toByteArray();
    }

    private TransformDump() {
    }
}