import ghidra.program.model.lang.Register;
import ghidra.program.util.VarnodeContext;
import java.util.ArrayList;
import java.lang.Integer;

public class RegisterProperties {

	private String register_name;
	private String base_register;
	private String parent_register = null;
	private ArrayList<String> children = new ArrayList<String>();
	private long lsbyte_in_base;
	private long size;
	// Offset into the register address space.
	private long address_space_offset;
	private long bytes_spanned;
	private long bit_length;
	private boolean is_zero;
	private boolean is_processor_context;
	private boolean is_base_register;
	private boolean is_big_endian;

	public RegisterProperties(Register register, VarnodeContext context) {

		this.register_name = register.getName();
		this.base_register = register.getBaseRegister().getName();
		if (!register.isBaseRegister()) {
			this.parent_register = register.getParentRegister().getName();
		}
		for (Register child : register.getChildRegisters()) {
			this.children.add(child.getName());
		}

		this.lsbyte_in_base = Integer.toUnsignedLong((int) (register.getLeastSignificantBitInBaseRegister() / 8));
		this.size = Integer.toUnsignedLong(context.getRegisterVarnode(register).getSize());

		this.address_space_offset = Integer.toUnsignedLong(register.getOffset());
		this.bytes_spanned = Integer.toUnsignedLong(register.getNumBytes());
		this.bit_length = Integer.toUnsignedLong(register.getBitLength());

		this.is_zero = register.isZero();
		this.is_processor_context = register.isProcessorContext();
		this.is_base_register = register.isBaseRegister();
		this.is_big_endian = register.isBigEndian();
	}
}
