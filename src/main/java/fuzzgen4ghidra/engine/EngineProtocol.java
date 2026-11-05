package fuzzgen4ghidra.engine;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class EngineProtocol {

	private static final Gson GSON = new GsonBuilder().create();

	public static class Command {
		private final String type;
		private final Map<String, Object> params;

		public Command(String type, Map<String, Object> params) {
			this.type = type;
			this.params = params;
		}

		public String getType() { return type; }
		public Map<String, Object> getParams() { return params; }
	}

	public static class Response {
		private String status;
		private JsonObject data;
		private String message;

		public boolean isOk() { return "ok".equals(status); }
		public boolean isError() { return "error".equals(status); }
		public boolean isProgress() { return "progress".equals(status); }
		public String getStatus() { return status; }
		public JsonObject getData() { return data; }
		public String getMessage() { return message; }

		public String getDataString(String key) {
			if (data == null || !data.has(key)) return null;
			JsonElement el = data.get(key);
			return el.isJsonNull() ? null : el.getAsString();
		}

		public long getDataLong(String key, long defaultValue) {
			if (data == null || !data.has(key)) return defaultValue;
			return data.get(key).getAsLong();
		}

		public boolean getDataBoolean(String key, boolean defaultValue) {
			if (data == null || !data.has(key)) return defaultValue;
			JsonElement el = data.get(key);
			return el.isJsonNull() ? defaultValue : el.getAsBoolean();
		}

		public JsonArray getDataArray(String key) {
			if (data == null || !data.has(key)) return null;
			return data.getAsJsonArray(key);
		}
	}

	public static String serialize(Command cmd) {
		return GSON.toJson(cmd);
	}

	public static Response deserialize(String json) {
		return GSON.fromJson(json, Response.class);
	}

	// --- Command factory methods ---

	public static Command initCmd(String binaryPath) {
		Map<String, Object> params = new HashMap<>();
		params.put("binary_path", binaryPath);
		return new Command("init", params);
	}

	public static Command scanTargetsCmd(String ghidraFunctionsJson) {
		Map<String, Object> params = new HashMap<>();
		params.put("ghidra_functions", GSON.fromJson(ghidraFunctionsJson, Object.class));
		return new Command("scan_targets", params);
	}

	public static Command analyzeParamsCmd(String funcAddr, String ghidraSignatureJson) {
		Map<String, Object> params = new HashMap<>();
		params.put("func_addr", funcAddr);
		params.put("ghidra_signature", GSON.fromJson(ghidraSignatureJson, Object.class));
		return new Command("analyze_params", params);
	}

	public static Command generateHarnessCmd(
			String funcAddr, String funcName, String ghidraSignatureJson,
			String targetBinary, String fmt, String outputDir) {
		return generateHarnessCmd(funcAddr, funcName, ghidraSignatureJson, targetBinary,
			fmt, outputDir, null, null, null, null, null);
	}

	/**
	 * Full harness generation command.
	 *
	 * @param targetPlatform "auto", "android" or "host" (null = auto)
	 * @param ndkApi         Android API level for the NDK toolchain (null = default)
	 * @param callMode       "auto", "dlsym" or "address" (null = auto)
	 * @param jniMode        "auto", "off", "env" or "onload" (null = auto)
	 * @param runJniOnload   call JNI_OnLoad before fuzzing (null = auto)
	 */
	public static Command generateHarnessCmd(
			String funcAddr, String funcName, String ghidraSignatureJson,
			String targetBinary, String fmt, String outputDir,
			String targetPlatform, Integer ndkApi, String callMode,
			String jniMode, Boolean runJniOnload) {
		Map<String, Object> params = new HashMap<>();
		params.put("func_addr", funcAddr);
		params.put("func_name", funcName);
		params.put("ghidra_signature", GSON.fromJson(ghidraSignatureJson, Object.class));
		params.put("target_binary", targetBinary);
		params.put("fmt", fmt);
		if (outputDir != null) {
			params.put("output_dir", outputDir);
		}
		if (targetPlatform != null && !targetPlatform.isBlank()) {
			params.put("target_platform", targetPlatform);
		}
		if (ndkApi != null && ndkApi > 0) {
			params.put("ndk_api", ndkApi);
		}
		if (callMode != null && !callMode.isBlank()) {
			params.put("call_mode", callMode);
		}
		if (jniMode != null && !jniMode.isBlank()) {
			params.put("jni_mode", jniMode);
		}
		if (runJniOnload != null) {
			params.put("run_jni_onload", runJniOnload);
		}
		return new Command("generate_harness", params);
	}
}
