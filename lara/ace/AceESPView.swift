//
//  AceESPView.swift  —  ESP 控制页
//

import SwiftUI

struct AceESPView: View {
    @State private var processName: String = AceESP.shared().targetProcess
    @State private var running: Bool = false
    @State private var playerCount: Int = 0
    @State private var logs: [String] = []
    @State private var poller: Timer? = nil

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                HStack {
                    Text("目标进程").font(.headline)
                    Spacer()
                }
                TextField("例如 AceForce", text: $processName)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)

                Button {
                    if running { stop() } else { start() }
                } label: {
                    HStack {
                        Image(systemName: running ? "stop.circle.fill" : "play.circle.fill")
                        Text(running ? "停止 ESP" : "启动 ESP")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(running ? Color.red.opacity(0.85) : Color.accentColor)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                }

                HStack {
                    Circle()
                        .fill(running ? Color.green : Color.gray)
                        .frame(width: 10, height: 10)
                    Text(running ? "运行中" : "未运行")
                    Spacer()
                    Text("实体 \(playerCount)").foregroundStyle(.secondary)
                }
                .font(.subheadline)

                Divider()

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
                .background(Color.secondary.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 10))

                Text("先确认进程名，再启动。游戏需已在前台运行。")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding()
            .navigationTitle("ESP")
            .onAppear {
                AceESP.shared().logBlock = { line in
                    logs.append(line)
                    if logs.count > 400 { logs.removeFirst(logs.count - 400) }
                }
                running = AceESP.shared().running
                startPolling()
            }
            .onDisappear {
                poller?.invalidate()
                poller = nil
            }
        }
    }

    private func start() {
        AceESP.shared().targetProcess = processName
        _ = AceESP.shared().start()
        running = AceESP.shared().running
        if !running && logs.isEmpty {
            logs.append("启动失败：看日志判断卡在哪一步")
        }
    }

    private func stop() {
        AceESP.shared().stop()
        running = false
        playerCount = 0
    }

    private func startPolling() {
        poller?.invalidate()
        poller = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            playerCount = Int(AceESP.shared().lastPlayerCount)
            running = AceESP.shared().running
        }
    }
}
