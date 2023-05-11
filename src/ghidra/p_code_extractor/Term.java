import ghidra.program.util.VarnodeContext;

public class Term {
	private String address;
	private int index;
	private PcodeOp operation;

	public Term(String address,
	            int index,
	            ghidra.program.model.pcode.PcodeOp operation,
	            VarnodeContext context,
	            DatatypeProperties datatypeProperties) {
		this.address = address;
		this.index = index;
		this.operation = new PcodeOp(index, operation, context, datatypeProperties);
	}
}
