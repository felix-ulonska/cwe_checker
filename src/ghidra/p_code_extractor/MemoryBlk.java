import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import java.io.IOException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.address.Address;

/**
 * Wrapper class for MemoryBlock
 *
 * This model is designed for the cwe_checker's Sub equivalent.
 * This class is used for clean and simple serialization.
 */

public class MemoryBlk {
    public String name;
    public String base_address;
    public String data;
    public long size;
    public boolean is_executable;
    public boolean is_readable;
    public boolean is_writeable;


    public MemoryBlk(MemoryBlock memBlock) throws IOException, MemoryAccessException {
        this.name = memBlock.getName();
        this.size = memBlock.getSize();
        byte[] data = new byte[(int) memBlock.getSize()];
        Address start = memBlock.getStart();
        this.base_address = start.getPhysicalAddress().toString();
        memBlock.getBytes(start, data);
        this.data = bytesToHex(data);
        this.is_executable = memBlock.isExecute();
        this.is_readable = memBlock.isRead();
        this.is_writeable = memBlock.isWrite();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
