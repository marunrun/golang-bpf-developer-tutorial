// File: GcLoop.java
public class GcLoop {
    public static void main(String[] args) throws InterruptedException {
        System.out.println("开始触发 GC 循环...");
        while (true) {
            // 分配较大对象，触发 Minor GC
            byte[] buffer = new byte[10 * 1024 * 1024]; // 10 MB
            buffer = null; // 取消引用，等待回收

            // 主动建议进行 Full GC
            System.gc();

            // 间隔暂停，防止 CPU 占用过高
            Thread.sleep(500);
        }
    }
}