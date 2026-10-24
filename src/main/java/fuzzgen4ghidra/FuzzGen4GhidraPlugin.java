package fuzzgen4ghidra;

import java.io.IOException;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import fuzzgen4ghidra.actions.*;
import fuzzgen4ghidra.engine.EngineManager;
import fuzzgen4ghidra.engine.EngineProtocol;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "FuzzGen4Ghidra",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Automatic Fuzzing Harness Generation",
	description = "Generates AFL++/libFuzzer fuzzing harnesses for binary functions using angr analysis."
)
//@formatter:on
public class FuzzGen4GhidraPlugin extends Plugin {

	private EngineManager engineManager;

	public FuzzGen4GhidraPlugin(PluginTool tool) {
		super(tool);
		engineManager = new EngineManager();
		new GenerateHarnessAction(this);
		new ScanTargetsAction(this);
	}

	public EngineManager getEngineManager() {
		return engineManager;
	}

	public void ensureEngineStarted() {
		if (!engineManager.isRunning()) {
			try {
				engineManager.start();
			}
			catch (Exception e) {
				Msg.showError(this, null, "FuzzGen4Ghidra",
					"Failed to start engine: " + e.getMessage(), e);
				return;
			}
		}
		ensureInitialized();
	}

	public boolean ensureInitialized() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null) return false;
		Program program = pm.getCurrentProgram();
		if (program == null) return false;

		String path = program.getExecutablePath();
		if (path == null || path.isBlank()) {
			Msg.showError(this, null, "FuzzGen4Ghidra",
				"Could not determine the file path of the current program.");
			return false;
		}

		if (!engineManager.isRunning()) {
			Msg.showError(this, null, "FuzzGen4Ghidra",
				"Engine is not running.");
			return false;
		}

		try {
			EngineProtocol.Response resp = engineManager.sendCommand(
				EngineProtocol.initCmd(path));
			if (resp.isOk()) {
				Msg.info(this, "Initialized engine with: " + path);
				return true;
			}
			Msg.showError(this, null, "FuzzGen4Ghidra",
				"Failed to load binary: " + resp.getMessage());
			return false;
		}
		catch (IOException e) {
			Msg.showError(this, null, "FuzzGen4Ghidra",
				"Lost connection to engine: " + e.getMessage());
			engineManager.stop();
			return false;
		}
	}

	@Override
	protected void dispose() {
		engineManager.dispose();
		super.dispose();
	}
}
