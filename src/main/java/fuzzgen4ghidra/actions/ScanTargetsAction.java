package fuzzgen4ghidra.actions;

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.Msg;
import fuzzgen4ghidra.FuzzGen4GhidraPlugin;
import fuzzgen4ghidra.engine.EngineProtocol;
import fuzzgen4ghidra.engine.EngineProtocol.Response;

public class ScanTargetsAction extends DockingAction {

	private static final Gson GSON = new Gson();
	private final FuzzGen4GhidraPlugin plugin;

	public ScanTargetsAction(FuzzGen4GhidraPlugin plugin) {
		super("Scan Fuzz Targets", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(
			new String[] { "FuzzGen4Ghidra", "Scan Fuzz Targets" },
			null, "FuzzGen"));

		plugin.getTool().addAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		ProgramManager pm = plugin.getTool().getService(ProgramManager.class);
		return pm != null && pm.getCurrentProgram() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.ensureEngineStarted();
		if (!plugin.getEngineManager().isRunning()) return;

		ProgramManager pm = plugin.getTool().getService(ProgramManager.class);
		Program program = pm.getCurrentProgram();
		if (program == null) return;

		List<Object> funcList = new ArrayList<>();
		FunctionIterator iter = program.getFunctionManager().getFunctions(true);
		while (iter.hasNext()) {
			Function func = iter.next();
			if (func.isExternal() || func.isThunk()) continue;

			java.util.Map<String, Object> fInfo = new java.util.HashMap<>();
			fInfo.put("address", "0x" + func.getEntryPoint().toString());
			fInfo.put("name", func.getName());
			fInfo.put("param_count", func.getParameterCount());

			boolean hasBuffer = false;
			for (ghidra.program.model.listing.Parameter p : func.getParameters()) {
				String typeName = p.getDataType().toString().toLowerCase();
				if (typeName.contains("*") && (typeName.contains("char") ||
					typeName.contains("byte") || typeName.contains("void") ||
					typeName.contains("uint8"))) {
					hasBuffer = true;
					break;
				}
			}
			fInfo.put("has_buffer_param", hasBuffer);
			funcList.add(fInfo);
		}

		String functionsJson = GSON.toJson(funcList);

		plugin.getEngineManager().sendCommandWithProgressAsync(
			EngineProtocol.scanTargetsCmd(functionsJson),
			progress -> SwingUtilities.invokeLater(() -> {
				JsonObject d = progress.getData();
				if (d != null) {
					Msg.info(this, String.format("Scanning: %d / %d",
						d.has("scanned") ? d.get("scanned").getAsInt() : 0,
						d.has("total") ? d.get("total").getAsInt() : 0));
				}
			})
		).thenAccept(response -> {
			SwingUtilities.invokeLater(() -> {
				if (response.isError()) {
					Msg.showError(this, null, "FuzzGen4Ghidra",
						"Scan failed: " + response.getMessage());
					return;
				}
				JsonObject data = response.getData();
				if (data == null || !data.has("targets")) {
					Msg.showInfo(this, null, "FuzzGen4Ghidra", "No targets found.");
					return;
				}
				JsonArray targets = data.getAsJsonArray("targets");
				StringBuilder sb = new StringBuilder();
				sb.append("Top Fuzz Targets:\n\n");
				sb.append(String.format("%-40s %-8s %-6s %s\n", "Function", "Score", "Blocks", "Reasons"));
				sb.append("-".repeat(90)).append("\n");
				int count = 0;
				for (JsonElement el : targets) {
					if (count++ >= 20) break;
					JsonObject t = el.getAsJsonObject();
					String name = t.get("name").getAsString();
					double score = t.get("score").getAsDouble();
					int complexity = t.get("complexity").getAsInt();
					JsonArray reasons = t.getAsJsonArray("reasons");
					List<String> reasonStrs = new ArrayList<>();
					for (JsonElement r : reasons) reasonStrs.add(r.getAsString());
					sb.append(String.format("%-40s %-8.1f %-6d %s\n",
						name.length() > 39 ? name.substring(0, 39) : name,
						score, complexity, String.join("; ", reasonStrs)));
				}
				Msg.showInfo(this, null, "FuzzGen4Ghidra — Scan Results",
					sb.toString());
			});
		}).exceptionally(e -> {
			SwingUtilities.invokeLater(() ->
				Msg.showError(this, null, "FuzzGen4Ghidra",
					"Scan error: " + e.getMessage()));
			return null;
		});
	}
}
