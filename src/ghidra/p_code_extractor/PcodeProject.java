import java.util.ArrayList;
import java.util.HashMap;
import java.util.ArrayList;
import ghidra.program.model.lang.Endian;

/**
 * Wrapper class for all collected information.
 *
 * This class is used for clean and simple serialization.
 */
public class PcodeProject {

    private Program program;
    private ArrayList<RegisterProperties> register_properties;
    private String cpu_arch;
    private HashMap<String, ExternFunction> external_functions;
    private ArrayList<String> entry_points;
    private Varnode stack_pointer_register;
    private HashMap<String, CallingConvention> calling_conventions;
    private DatatypeProperties datatype_properties;
    private String image_base;
    private ArrayList<MemoryBlk> mem_blocks;
    private ArrayList<CodeRef> code_refs;
    private boolean is_big_endian;

    public PcodeProject(ArrayList<Function> functions,
            ArrayList<RegisterProperties> register_properties,
            String cpu_arch,
            boolean is_big_endian,
            HashMap<String, ExternFunction> external_functions,
            ArrayList<String> entry_points,
            Varnode stack_pointer_register,
	    HashMap<String, CallingConvention> calling_conventions,
            DatatypeProperties datatype_properties,
	    String image_base, ArrayList<MemoryBlk> memBlocks,
                        ArrayList<CodeRef> code_refs) {
        this.program = new Program(functions);
        this.register_properties = register_properties;
        this.cpu_arch = cpu_arch;
        this.external_functions = external_functions;
        this.entry_points = entry_points;
        this.stack_pointer_register = stack_pointer_register;
	this.calling_conventions = calling_conventions;
        this.datatype_properties = datatype_properties;
	this.image_base = image_base;
        this.mem_blocks = memBlocks;
        this.code_refs = code_refs;
    }

}
