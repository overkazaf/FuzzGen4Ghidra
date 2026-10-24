package fuzzgen4ghidra.actions;

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import fuzzgen4ghidra.FuzzGen4GhidraPlugin;
import fuzzgen4ghidra.engine.EngineProtocol;
import fuzzgen4ghidra.engine.EngineProtocol.Response;
import fuzzgen4ghidra.ui.HarnessPreviewDialog;

public class GenerateHarnessAction extends DockingAction {

	private static final Gson GSON = new Gson();
	private final FuzzGen4GhidraPlugin plugin;

	public GenerateHarnessAction(FuzzGen4GhidraPlugin plugin) {
		super("Generate Fuzz Harness", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { "FuzzGen4Ghidra", "Generate Fuzz Harness" },
			null, "FuzzGen"));

		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof ListingActionContext)) return false;
		ListingActionContext lac = (ListingActionContext) context;
		Program program = lac.getProgram();
		if (program == null) return false;
		Address addr = lac.getAddress();
		return addr != null && program.getFunctionManager().getFunctionContaining(addr) != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ListingActionContext lac = (ListingActionContext) context;
		Program program = lac.getProgram();
		Address addr = lac.getAddress();
		Function func = program.getFunctionManager().getFunctionContaining(addr);
		if (func == null) return;

		plugin.ensureEngineStarted();
		if (!plugin.getEngineManager().isRunning()) return;

		String funcName = func.getName();
		String funcAddr = "0x" + func.getEntryPoint().toString();
		String binaryName = program.getExecutablePath();
		// Extract just the filename
		int lastSlash = binaryName.lastIndexOf('/');
		if (lastSlash >= 0) binaryName = binaryName.substring(lastSlash + 1);

		String sigJson = buildGhidraSignature(func, program);

		final String targetBinary = binaryName;
		plugin.getEngineManager().sendCommandAsync(
			EngineProtocol.generateHarnessCmd(funcAddr, funcName, sigJson, targetBinary, "afl", null)
		).thenAccept(response -> {
			SwingUtilities.invokeLater(() -> {
				if (response.isError()) {
					Msg.showError(this, null, "FuzzGen4Ghidra",
						"Harness generation failed: " + response.getMessage());
					return;
				}
				JsonObject data = response.getData();
				String harnessCode = data.has("harness_code")
					? data.get("harness_code").getAsString() : "";
				String typesHeader = data.has("types_header")
					? data.get("types_header").getAsString() : "";
				String makefile = data.has("makefile")
					? data.get("makefile").getAsString() : "";

				new HarnessPreviewDialog(plugin, funcName, funcAddr,
					sigJson, targetBinary, harnessCode, typesHeader, makefile);
			});
		}).exceptionally(e -> {
			SwingUtilities.invokeLater(() ->
				Msg.showError(this, null, "FuzzGen4Ghidra",
					"Error: " + e.getMessage()));
			return null;
		});
	}

	private String buildGhidraSignature(Function func, Program program) {
		List<Object> paramsList = new ArrayList<>();

		// Try decompiler for better types
		DecompInterface decomp = new DecompInterface();
		try {
			decomp.openProgram(program);
			DecompileResults results = decomp.decompileFunction(func, 30, null);
			if (results != null && results.decompileCompleted()) {
				ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
				if (highFunc != null) {
					ghidra.program.model.pcode.LocalSymbolMap symbolMap = highFunc.getLocalSymbolMap();
					int paramCount = symbolMap.getNumParams();
					for (int i = 0; i < paramCount; i++) {
						ghidra.program.model.pcode.HighSymbol sym = symbolMap.getParamSymbol(i);
						java.util.Map<String, Object> p = new java.util.HashMap<>();
						p.put("name", sym.getName());
						p.put("type", sym.getDataType().toString());
						p.put("size", sym.getSize());
						paramsList.add(p);
					}
					java.util.Map<String, Object> sig = new java.util.HashMap<>();
					sig.put("params", paramsList);
					return GSON.toJson(sig);
				}
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Decompiler failed, falling back to listing params: " + e.getMessage());
		}
		finally {
			decomp.dispose();
		}

		// Fallback: use listing parameters
		for (Parameter param : func.getParameters()) {
			java.util.Map<String, Object> p = new java.util.HashMap<>();
			p.put("name", param.getName());
			p.put("type", param.getDataType().toString());
			p.put("size", param.getLength());
			paramsList.add(p);
		}
		java.util.Map<String, Object> sig = new java.util.HashMap<>();
		sig.put("params", paramsList);
		return GSON.toJson(sig);
	}
}
