//
//  AceESPView.swift  —  ESP 控制页
//

import SwiftUI

struct AceESPView: View {
    @State private var processName: String = AceESP.shared().targetProcess
    @State private var running: Bool = false
    @State private var busy: Bool = false
    @State private var drawing: Bool = false
    @State private var playerCount: Int = 0
    @State private var targetCount: Int = 0
    @State private var logs: [String] = []
    @State private var poller: Timer? = nil

    @State private var optBox = true
    @State private var optLine = true
    @State private var optName = true
    @State private var optHealth = true
    @State private var optDistance = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    sectionTitle("目标进程")
                    TextField("可执行文件名，例如 heroios", text: $processName)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)

                    HStack(spacing: 10) {
                        Button {
                            if running { stop() } else { start() }
                        } label: {
                            HStack {
                                if busy { ProgressView().tint(.white) }
                                else { Image(systemName: running ? "stop.circle.fill" : "play.circle.fill") }
                                Text(busy ? "初始化中…" : (running ? "停止 ESP" : "启动 ESP"))
                                    .fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 13)
                            .background(running ? Color.red.opacity(0.85) : Color.accentColor)
                            .foregroundStyle(.white)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                        .disabled(busy)

                        Button {
                            AceESP.shared().listProcessesAsync()
                        } label: {
                            Image(systemName: "list.bullet.rectangle")
                                .padding(.vertical, 13).padding(.horizontal, 16)
                                .background(Color.secondary.opacity(0.18))
                                .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                        .disabled(busy)
                    }

                    HStack {
                        Circle().fill(running ? Color.green : Color.gray).frame(width: 10, height: 10)
                        Text(busy ? "初始化中" : (running ? "运行中" : "未运行"))
                        Spacer()
                        Text("玩家 \(playerCount) · 绘制 \(targetCount)").foregroundStyle(.secondary)
                    }
                    .font(.subheadline)

                    Button {
                        AceESP.shared().diagnoseAsync()
                    } label: {
                        HStack {
                            Image(systemName: "stethoscope")
                            Text("① 内核自检")
                            Spacer()
                        }
                        .padding(.vertical, 11).padding(.horizontal, 14)
                        .background(Color.blue.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .disabled(busy)

                    Button {
                        AceESP.shared().prepareOffsetsAsync()
                    } label: {
                        HStack {
                            Image(systemName: "arrow.down.circle")
                            Text("② 准备内核偏移（下载 kernelcache）")
                            Spacer()
                        }
                        .padding(.vertical, 11).padding(.horizontal, 14)
                        .background(Color.purple.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .disabled(busy)

                    Button {
                        AceESP.shared().testSpringBoardAsync()
                    } label: {
                        HStack {
                            Image(systemName: "arrow.triangle.2.circlepath")
                            Text("③ 对照测试：连接 SpringBoard")
                            Spacer()
                        }
                        .padding(.vertical, 11).padding(.horizontal, 14)
                        .background(Color.teal.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .disabled(busy)

                    Button {
                        AceESP.shared().diagnosePACAsync()
                    } label: {
                        HStack {
                            Image(systemName: "lock.shield")
                            Text("④ PAC 诊断（查 pc=0x201 的根因）")
                            Spacer()
                        }
                        .padding(.vertical, 11).padding(.horizontal, 14)
                        .background(Color.orange.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .disabled(busy)

                    Button {
                        AceESP.shared().testInjectSelfAsync()
                    } label: {
                        HStack {
                            Image(systemName: "person.crop.circle")
                            Text("⑤ 注入对照：连接 lara 自己")
                            Spacer()
                        }
                        .padding(.vertical, 11).padding(.horizontal, 14)
                        .background(Color.indigo.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .disabled(busy)

                    Button {
                        AceESP.shared().diagnoseSuspendAsync()
                    } label: {
                        HStack {
                            Image(systemName: "pause.circle")
                            Text("⑥ 挂起诊断（找 suspend_count）")
                            Spacer()
                        }
                        .padding(.vertical, 11).padding(.horizontal, 14)
                        .background(Color.pink.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .disabled(busy)

                    HStack(spacing: 10) {
                        Button {
                            AceESP.shared().wakeTargetAsync()
                        } label: {
                            HStack {
                                Image(systemName: "bolt.fill")
                                Text("⑦ 唤醒进程（改内核）")
                                Spacer()
                            }
                            .padding(.vertical, 12).padding(.horizontal, 14)
                            .background(Color.red.opacity(0.2))
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                        }
                        .disabled(busy)

                        Button {
                            AceESP.shared().restoreSuspendAsync()
                        } label: {
                            Image(systemName: "arrow.uturn.backward")
                                .padding(.vertical, 12).padding(.horizontal, 16)
                                .background(Color.secondary.opacity(0.18))
                                .clipShape(RoundedRectangle(cornerRadius: 10))
                        }
                        .disabled(busy)
                    }

                    // ---- 绘制 ----
                    sectionTitle("绘制")
                    Button {
                        if drawing { AceESP.shared().stopOverlayAsync(); drawing = false }
                        else { startDrawing() }
                    } label: {
                        HStack {
                            Image(systemName: drawing ? "eye.slash.fill" : "eye.fill")
                            Text(drawing ? "关闭绘制" : "开启绘制")
                            Spacer()
                        }
                        .padding(.vertical, 12).padding(.horizontal, 14)
                        .background(drawing ? Color.orange.opacity(0.85) : Color.green.opacity(0.8))
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .disabled(!running)

                    VStack(spacing: 0) {
                        toggleRow("敌人包围盒", $optBox) { AceESP.shared().optBox = $0 }
                        Divider()
                        toggleRow("连线", $optLine) { AceESP.shared().optLine = $0 }
                        Divider()
                        toggleRow("名字", $optName) { AceESP.shared().optName = $0 }
                        Divider()
                        toggleRow("血条", $optHealth) { AceESP.shared().optHealth = $0 }
                        Divider()
                        toggleRow("距离", $optDistance) { AceESP.shared().optDistance = $0 }
                    }
                    .background(Color.secondary.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 10))

                    // ---- 日志 ----
                    HStack {
                        Text("日志").font(.headline)
                        Spacer()
                        Button("清空") { logs.removeAll() }.font(.caption)
                    }

                    ScrollView {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(Array(logs.enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.system(size: 11, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding(8)
                    }
                    .frame(minHeight: 200)
                    .background(Color.secondary.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 10))

                    Text("进程名是可执行文件名，不是 Bundle ID。初始化十几秒属正常，期间界面不会卡。")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding()
            }
            .navigationTitle("ESP")
            .onAppear {
                AceESP.shared().logBlock = { line in
                    DispatchQueue.main.async {
                        logs.append(line)
                        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
                    }
                }
                running = AceESP.shared().running
                drawing = AceESP.shared().drawing
                startPolling()
            }
            .onDisappear {
                poller?.invalidate()
                poller = nil
            }
        }
    }

    @ViewBuilder
    private func sectionTitle(_ s: String) -> some View {
        HStack { Text(s).font(.headline); Spacer() }
    }

    private func toggleRow(_ title: String, _ binding: Binding<Bool>,
                           _ apply: @escaping (Bool) -> Void) -> some View {
        Toggle(isOn: Binding(
            get: { binding.wrappedValue },
            set: { newValue in
                binding.wrappedValue = newValue
                apply(newValue)
            }
        )) { Text(title) }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    private func start() {
        busy = true
        AceESP.shared().targetProcess = processName
        AceESP.shared().startAsync { ok in
            busy = false
            running = ok
            if ok { AceESP.shared().dumpOnceAsync() }
            else { appendLog("启动失败：看上面日志判断卡在哪一步") }
        }
    }

    private func startDrawing() {
        AceESP.shared().startOverlayAsync { ok in
            drawing = ok
            if !ok { appendLog("绘制开启失败：看上面日志") }
        }
    }

    private func stop() {
        AceESP.shared().stopOverlayAsync()
        AceESP.shared().stop()
        running = false
        drawing = false
        playerCount = 0
        targetCount = 0
    }

    private func appendLog(_ s: String) {
        logs.append(s)
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
    }

    private func startPolling() {
        poller?.invalidate()
        poller = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            playerCount = Int(AceESP.shared().lastPlayerCount)
            targetCount = Int(AceESP.shared().lastTargetCount)
            if !busy {
                running = AceESP.shared().running
                drawing = AceESP.shared().drawing
            }
        }
    }
}
