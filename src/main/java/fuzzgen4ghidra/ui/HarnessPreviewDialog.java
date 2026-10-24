package fuzzgen4ghidra.ui;

import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import javax.swing.*;

import ghidra.util.Msg;
import fuzzgen4ghidra.FuzzGen4GhidraPlugin;
import fuzzgen4ghidra.engine.EngineProtocol;

public class HarnessPreviewDialog extends JDialog {

	private final FuzzGen4GhidraPlugin plugin;
	private final String funcName;
	private final String funcAddr;
	private final String sigJson;
	private final String targetBinary;

	private JTextArea codeArea;
	private JComboBox<String> fmtCombo;
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
		setSize(800, 600);
		setLocationRelativeTo(null);
		setVisible(true);
	}

	private void buildUI() {
		setLayout(new BorderLayout(8, 8));

		// Top panel: format selector
		JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		topPanel.add(new JLabel("Format:"));
		fmtCombo = new JComboBox<>(new String[] { "afl", "libfuzzer" });
		fmtCombo.addActionListener(e -> regenerate());
		topPanel.add(fmtCombo);
		add(topPanel, BorderLayout.NORTH);

		// Center: code preview
		codeArea = new JTextArea(currentHarness);
		codeArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
		codeArea.setEditable(false);
		codeArea.setTabSize(4);
		add(new JScrollPane(codeArea), BorderLayout.CENTER);

		// Bottom: save button
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

	private void regenerate() {
		String fmt = (String) fmtCombo.getSelectedItem();
		plugin.getEngineManager().sendCommandAsync(
			EngineProtocol.generateHarnessCmd(funcAddr, funcName, sigJson, targetBinary, fmt, null)
		).thenAccept(response -> {
			SwingUtilities.invokeLater(() -> {
				if (response.isError()) {
					Msg.showError(this, this, "FuzzGen4Ghidra",
						"Regeneration failed: " + response.getMessage());
					return;
				}
				var data = response.getData();
				currentHarness = data.has("harness_code")
					? data.get("harness_code").getAsString() : "";
				currentTypesHeader = data.has("types_header")
					? data.get("types_header").getAsString() : "";
				currentMakefile = data.has("makefile")
					? data.get("makefile").getAsString() : "";
				codeArea.setText(currentHarness);
				codeArea.setCaretPosition(0);
			});
		});
	}

	private void saveToDirectory() {
		JFileChooser chooser = new JFileChooser();
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		chooser.setDialogTitle("Save Harness Files to...");
		if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

		File dir = chooser.getSelectedFile();
		dir.mkdirs();
		try {
			writeFile(new File(dir, "harness_" + funcName + ".c"), currentHarness);
			writeFile(new File(dir, "types.h"), currentTypesHeader);
			writeFile(new File(dir, "Makefile"), currentMakefile);
			File seedsDir = new File(dir, "seeds");
			seedsDir.mkdirs();
			writeFile(new File(seedsDir, "seed_000"), new String(new byte[16]));
			Msg.showInfo(this, this, "FuzzGen4Ghidra",
				"Harness saved to: " + dir.getAbsolutePath());
		}
		catch (IOException e) {
			Msg.showError(this, this, "FuzzGen4Ghidra",
				"Failed to save: " + e.getMessage());
		}
	}

	private static void writeFile(File f, String content) throws IOException {
		try (FileWriter w = new FileWriter(f)) {
			w.write(content);
		}
	}
}
