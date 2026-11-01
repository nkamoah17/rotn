import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.FileInputStream;
import java.lang.reflect.Method;

/** Debug harness: prints the real node list of Bus#record and what the agent's walker returns. */
public final class WalkDebug {
    private WalkDebug() {
    }

    public static void main(String[] args) throws Exception {
        ClassReader cr = new ClassReader(new FileInputStream(args[0]));
        ClassNode cn = new ClassNode();
        cr.accept(cn, 0);
        MethodNode rec = null;
        for (MethodNode mn : cn.methods) {
            if (mn.name.equals("record") && mn.desc.equals("(Lcom/rot/n/twopc/TraceEvent;)V")) {
                rec = mn;
            }
        }
        if (rec == null) {
            throw new IllegalStateException("record(TraceEvent) not found");
        }
        int i = 0;
        for (AbstractInsnNode n : rec.instructions) {
            String extra = "";
            if (n instanceof JumpInsnNode) {
                JumpInsnNode j = (JumpInsnNode) n;
                extra = " labelNode@" + System.identityHashCode(j.label)
                        + " labelObj@" + (j.label == null ? "null"
                        : System.identityHashCode(j.label.getLabel()));
            } else if (n instanceof LabelNode) {
                extra = " labelObj@" + System.identityHashCode(((LabelNode) n).getLabel());
            }
            System.out.printf("%2d %-45s type=%2d%s%n", i++, n.getClass().getName(),
                    n.getType(), extra);
        }
        Class<?> pa = Class.forName("com.rot.n.agent.ProbeAgent");
        Method m = pa.getDeclaredMethod("findInsertPoint", MethodNode.class);
        m.setAccessible(true);
        System.out.println("findInsertPoint -> " + m.invoke(null, rec));
    }
}