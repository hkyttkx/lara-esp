//
//  AceOffsets.h
//  王牌战争 ESP — 结构偏移表
//
//  来源：Il2CppDump (Assembly-CSharp)，2026-10 版本
//  游戏更新后只需要改这一个文件。
//
#ifndef ACE_OFFSETS_H
#define ACE_OFFSETS_H

#pragma mark - 程序集 / 入口类
#define ACE_ASSEMBLY            "Assembly-CSharp"
#define ACE_CLASS_BATTLE        "Battle"

#pragma mark - Battle 静态字段
#define OFF_BATTLE_INS              0x88   // static Battle Ins

#pragma mark - Battle 实例字段
#define OFF_BATTLE_MAINCAMERA       0x28   // vThirdPersonCamera*
#define OFF_BATTLE_OTHERPLAYERSDIC  0x58   // Dictionary<long, OtherPlayerController*>
#define OFF_BATTLE_NEARPLAYERSDIC   0x60
#define OFF_BATTLE_CANSEE           0x68

#pragma mark - OtherPlayerController
#define OFF_OPC_INFO                0x3F0  // PlayerInfo*
#define OFF_OPC_WORLDPOS            0x43C  // Vector3（内联值类型，连续 12 字节）
#define OFF_OPC_ISVIRTUAL           0x41F  // bool — 虚拟玩家（诱饵），必须过滤
#define OFF_OPC_ISVISIBLE           0x468  // bool
#define OFF_OPC_REDNAME             0x438  // int32

#pragma mark - PlayerInfo
#define OFF_PI_CURSTATUS            0x10   // byte
#define OFF_PI_ROLEID               0x18   // int64
#define OFF_PI_NAME                 0x28   // Il2CppString*
#define OFF_PI_GROUPID              0x3C   // int32 阵营
#define OFF_PI_POS                  0x40   // Vec3*（引用类型，需二次解引用）
#define OFF_PI_HP                   0x64   // int32
#define OFF_PI_HPMAX                0x68   // int32

#pragma mark - Vec3（class）
#define OFF_VEC3_X                  0x10
#define OFF_VEC3_Y                  0x14
#define OFF_VEC3_Z                  0x18

#pragma mark - Il2CppString
#define OFF_STR_LEN                 0x10   // int32
#define OFF_STR_CHARS               0x14   // UTF-16

#pragma mark - Il2Cpp Dictionary<K,V>（64 位）
#define OFF_DICT_ENTRIES            0x18   // Entry* m_entries
#define OFF_DICT_COUNT              0x20   // int32 m_count
#define DICT_ENTRY_SIZE             0x18   // {int32 hashCode; int32 next; K key; V value;}
#define DICT_ENTRY_VALUE            0x10   // Entry 内 value 偏移

#pragma mark - Il2CppObject 通用头
#define OFF_IL2CPP_KLASS            0x00
#define OFF_IL2CPP_MONITOR          0x08
#define OFF_IL2CPP_BOXED_VALUE      0x10   // 装箱值类型的载荷起点

#pragma mark - curStatus 常量
#define ACE_ST_IN_ISLAND            1
#define ACE_ST_IN_PLANE             2
#define ACE_ST_LEAVE_PLANE          3
#define ACE_ST_OPEN_SAN             4
#define ACE_ST_ON_GROUND            5
#define ACE_ST_IN_WATER             6
#define ACE_ST_DIE                  11

#pragma mark - 相机
#define OFF_V3CAM_CAMERA            0x68   // vThirdPersonCamera._camera
#define ACE_UNITY_ASM               "UnityEngine.CoreModule"
#define ACE_UNITY_CAMERA_NS         "UnityEngine"
#define ACE_UNITY_CAMERA_CLASS      "Camera"

#pragma mark - 扫描参数
#define ACE_MAX_PLAYERS             128
#define ACE_SCRATCH_SIZE            0x1000

#endif /* ACE_OFFSETS_H */
