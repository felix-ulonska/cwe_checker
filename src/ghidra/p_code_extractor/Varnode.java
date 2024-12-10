import ghidra.program.util.VarnodeContext;
import ghidra.program.model.lang.Register;

/**
 * Wrapper class for Varnode
 * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/Varnode.html).
 *
 * Varnodes represent registers, stack offset and other values and are used as
 * operants for
 * pcode instructions.
 * This class is used for clean and simple serialization.
 */
public class Varnode {
	private int size;
	private String address_space;
	private String address_space_offset;
	private int pointer_size;
	private String register_name = null;
	private Integer register_size = null;

	public Varnode(ghidra.program.model.pcode.Varnode varnode, VarnodeContext context, DatatypeProperties datatypeProperties) {
		this.size = varnode.getSize();
		this.address_space = varnode.getAddress().getAddressSpace().getName();
		this.address_space_offset = varnode.getAddress().toString("0x");

		this.pointer_size = datatypeProperties.getPointerSize();

		Register register = context.getRegister(varnode);
		if (register != null) {
			this.register_name = register.getName();
			this.register_size = context.getRegisterVarnode(register).getSize();
		}
	}

	public Varnode(Register register) {
		this.size = (int) register.getBitLength() / 8;
		this.address_space = register.getAddressSpace().getName();
		this.address_space_offset = register.getAddress().toString("0x");
		// Not needed for register Varnodes.
		this.pointer_size = 0;
		this.register_name = register.getName();
		this.register_size = this.size;
	}

	public String toString() {
		return String.format("(%s, %s, %d)", this.address_space, this.address_space_offset, this.size);
	}

	public String getRegisterName() {
		return this.register_name;
	}

}
