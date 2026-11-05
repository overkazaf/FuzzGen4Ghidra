package fuzzgen4ghidra.ui;

import java.awt.*;
import java.io.File;

import javax.swing.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.util.Msg;
import fuzzgen4ghidra.FuzzGen4GhidraPlugin;
import fuzzgen4ghidra.engine.EngineProtocol;

/**
 * Shows a generated harness and lets the user switch format / platform /
 * resolution mode. The engine owns file layout, so "Save" asks it to write the
 * whole bundle (harness, types.h, Makefile, JNI stub, Android scripts).
 */
public class HarnessPreviewDialog extends JDialog {

	private final FuzzGen4GhidraPlugin plugin;
	private final String funcName;
	private final String funcAddr;
	private final String sigJson;
	private final String targetBinary;

	private JTextArea codeArea;
	private JComboBox<String> fmtCombo;
	private JComboBox<String> platformCombo;
	private JComboBox<String> callModeCombo;
	private JComboBox<String> jniModeCombo;
	private JTextField apiField;
	private JCheckBox onloadCheck;

	private String currentHarness;
	private String currentTypesHeader;
	private String currentMakefile;

	public HarnessPreviewDialog(FuzzGen4GhidraPlugin plugin,
			String funcName, String funcAddr, String sigJson, String targetBinary,
			String harnessCode, String typesHeader, String makefile) {
		super((Frame) null, "FuzzGen4Ghidra — " + funcName, false);
		this.plugin = plugin;
		this.funcName = funcName;
		this.funcAddr = funcAddr;
		this.sigJson = sigJson;
		this.targetBinary = targetBinary;
		this.currentHarness = harnessCode;
		this.currentTypesHeader = typesHeader;
		this.currentMakefile = makefile;

		buildUI();
		setSize(920, 680);
		setLocationRelativeTo(null);
		setVisible(true);
	}

	private void buildUI() {
		setLayout(new BorderLayout(8, 8));

		JPanel options = new JPanel();
		options.setLayout(new BoxLayout(options, BoxLayout.Y_AXIS));
		options.setBorder(BorderFactory.createEmptyBorder(6, 6, 0, 6));

		JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		row1.add(new JLabel("Format:"));
		fmtCombo = new JComboBox<>(new String[] { "afl", "libfuzzer" });
		fmtCombo.addActionListener(e -> regenerate());
		row1.add(fmtCombo);

		row1.add(new JLabel("Platform:"));
		platformCombo = new JComboBox<>(new String[] { "auto", "host", "android" });
		platformCombo.addActionListener(e -> regenerate());
		row1.add(platformCombo);

		row1.add(new JLabel("NDK API:"));
		apiField = new JTextField("21", 3);
		apiField.addActionListener(e -> regenerate());
		row1.add(apiField);

		options.add(row1);

		JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		row2.add(new JLabel("Call mode:"));
		callModeCombo = new JComboBox<>(new String[] { "auto", "dlsym", "address" });
		callModeCombo.setToolTipText(
			"auto: dlsym for exported symbols, load_bias+vaddr otherwise");
		callModeCombo.addActionListener(e -> regenerate());
		row2.add(callModeCombo);

		row2.add(new JLabel("JNI mode:"));
		jniModeCombo = new JComboBox<>(new String[] { "auto", "off", "env", "onload" });
		jniModeCombo.setToolTipText(
			"env: synthesise JNIEnv* for Java_* natives; onload: for JNI_OnLoad");
		jniModeCombo.addActionListener(e -> regenerate());
		row2.add(jniModeCombo);

		onloadCheck = new JCheckBox("Run JNI_OnLoad first", true);
		onloadCheck.addActionListener(e -> regenerate());
		row2.add(onloadCheck);

		options.add(row2);
		add(options, BorderLayout.NORTH);

		codeArea = new JTextArea(currentHarness);
		codeArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
		codeArea.setEditable(false);
		codeArea.setTabSize(4);
		add(new JScrollPane(codeArea), BorderLayout.CENTER);

		JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton saveBtn = new JButton("Save to Directory...");
		saveBtn.addActionListener(e -> saveToDirectory());
		bottomPanel.add(saveBtn);

		JButton copyBtn = new JButton("Copy to Clipboard");
		copyBtn.addActionListener(e -> {
			codeArea.selectAll();
			codeArea.copy();
			codeArea.setCaretPosition(0);
		});
		bottomPanel.add(copyBtn);

		add(bottomPanel, BorderLayout.SOUTH);
	}

	private String selectedPlatform() {
		return (String) platformCombo.getSelectedItem();
	}

	private Integer selectedApi() {
		try {
			return Integer.valueOf(apiField.getText().trim());
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	private EngineProtocol.Command buildCommand(String outputDir) {
		return EngineProtocol.generateHarnessCmd(
			funcAddr, funcName, sigJson, targetBinary,
			(String) fmtCombo.getSelectedItem(),
			outputDir,
			selectedPlatform(),
			selectedApi(),
			(String) callModeCombo.getSelectedItem(),
			(String) jniModeCombo.getSelectedItem(),
			onloadCheck.isSelected());
	}

	private void regenerate() {
		plugin.getEngineManager().sendCommandAsync(buildCommand(null))
			.thenAccept(response -> SwingUtilities.invokeLater(() -> {
				if (response.isError()) {
					Msg.showError(this, this, "FuzzGen4Ghidra",
						"Regeneration failed: " + response.getMessage());
					return;
				}
				JsonObject data = response.getData();
				currentHarness = getString(data, "harness_code");
				currentTypesHeader = getString(data, "types_header");
				currentMakefile = getString(data, "makefile");
				codeArea.setText(currentHarness);
				codeArea.setCaretPosition(0);
			}))
			.exceptionally(e -> {
				SwingUtilities.invokeLater(() -> Msg.showError(this, this,
					"FuzzGen4Ghidra", "Regeneration failed: " + e.getMessage()));
				return null;
			});
	}

	private void saveToDirectory() {
		JFileChooser chooser = new JFileChooser();
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		chooser.setDialogTitle("Save Harness Files to...");
		if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

		File dir = chooser.getSelectedFile();
		if (!dir.exists() && !dir.mkdirs()) {
			Msg.showError(this, this, "FuzzGen4Ghidra",
				"Could not create: " + dir.getAbsolutePath());
			return;
		}

		plugin.getEngineManager().sendCommandAsync(buildCommand(dir.getAbsolutePath()))
			.thenAccept(response -> SwingUtilities.invokeLater(() -> {
				if (response.isError()) {
					Msg.showError(this, this, "FuzzGen4Ghidra",
						"Failed to save: " + response.getMessage());
					return;
				}
				JsonObject data = response.getData();
				currentHarness = getString(data, "harness_code");
				currentTypesHeader = getString(data, "types_header");
				currentMakefile = getString(data, "makefile");
				codeArea.setText(currentHarness);

				StringBuilder files = new StringBuilder();
				if (data != null && data.has("files")) {
					JsonArray arr = data.getAsJsonArray("files");
					for (JsonElement el : arr) {
						files.append("\n  ").append(el.getAsString());
					}
				}
				Msg.showInfo(this, this, "FuzzGen4Ghidra",
					"Harness saved to: " + dir.getAbsolutePath()
						+ (files.length() > 0 ? "\n" + files : ""));
			}))
			.exceptionally(e -> {
				SwingUtilities.invokeLater(() -> Msg.showError(this, this,
					"FuzzGen4Ghidra", "Failed to save: " + e.getMessage()));
				return null;
			});
	}

	private static String getString(JsonObject data, String key) {
		if (data == null || !data.has(key) || data.get(key).isJsonNull()) return "";
		return data.get(key).getAsString();
	}
}
