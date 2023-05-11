import ghidra.program.util.VarnodeContext;
import java.util.ArrayList;

/**
 * Wrapper class for a simplified calling convention.
 *
 * This model is designed for the cwe_checker's calling convention equivalent.
 * This class is used for clean and simple serialization.
 */
public class CallingConvention {
	private String name;
	private ArrayList<Varnode> integer_parameter_register = new ArrayList<Varnode>();
	private ArrayList<Varnode> float_parameter_register = new ArrayList<Varnode>();
	private Varnode integer_return_register = null;
	private Varnode float_return_register = null;
	private ArrayList<Varnode> unaffected_register = new ArrayList<Varnode>();
	private ArrayList<Varnode> killed_by_call_register = new ArrayList<Varnode>();

	public CallingConvention(String name, ghidra.program.model.pcode.Varnode[] unaffected_register, ghidra.program.model.pcode.Varnode[] killed_by_call_register,
	                         VarnodeContext context, DatatypeProperties datatypeProperties) {
		this.name = name;
		for (ghidra.program.model.pcode.Varnode varnode : unaffected_register) {
			this.unaffected_register.add(new Varnode(varnode, context, datatypeProperties));
		}
		for (ghidra.program.model.pcode.Varnode varnode : killed_by_call_register) {
			this.killed_by_call_register.add(new Varnode(varnode, context, datatypeProperties));
		}
	}

	public void setIntegerParameterRegister(ArrayList<Varnode> integer_parameter_register) {
		this.integer_parameter_register = integer_parameter_register;
	}

	public void setFloatParameterRegister(ArrayList<Varnode> float_parameter_register) {
		this.float_parameter_register = float_parameter_register;
	}

	public void setIntegerReturnRegister(Varnode returnRegister) {
		this.integer_return_register = returnRegister;
	}

	public void setFloatReturnRegister(Varnode returnRegister) {
		this.float_return_register = returnRegister;
	}
}
