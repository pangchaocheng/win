// Copyright 2010 The win Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package win

import (
	"syscall"
	"unsafe"
)

const (
	S_OK           = 0x00000000
	S_FALSE        = 0x00000001
	E_UNEXPECTED   = 0x8000FFFF
	E_NOTIMPL      = 0x80004001
	E_OUTOFMEMORY  = 0x8007000E
	E_INVALIDARG   = 0x80070057
	E_NOINTERFACE  = 0x80004002
	E_POINTER      = 0x80004003
	E_HANDLE       = 0x80070006
	E_ABORT        = 0x80004004
	E_FAIL         = 0x80004005
	E_ACCESSDENIED = 0x80070005
	E_PENDING      = 0x8000000A
)

const (
	FALSE = 0
	TRUE  = 1
)

type (
	BOOL    int32
	HRESULT int32
)

const STANDARD_RIGHTS_REQUIRED = 0x000F0000

const (
	NO_ERROR                                = 0
	ERROR_PATH_NOT_FOUND                    = 3
	ERROR_TOO_MANY_OPEN_FILES               = 4
	ERROR_ACCESS_DENIED                     = 5
	ERROR_INVALID_HANDLE                    = 6
	ERROR_ARENA_TRASHED                     = 7
	ERROR_NOT_ENOUGH_MEMORY                 = 8
	ERROR_INVALID_BLOCK                     = 9
	ERROR_BAD_ENVIRONMENT                   = 10
	ERROR_BAD_FORMAT                        = 11
	ERROR_INVALID_ACCESS                    = 12
	ERROR_INVALID_DATA                      = 13
	ERROR_OUTOFMEMORY                       = 14
	ERROR_INVALID_DRIVE                     = 15
	ERROR_CURRENT_DIRECTORY                 = 16
	ERROR_NOT_SAME_DEVICE                   = 17
	ERROR_NO_MORE_FILES                     = 18
	ERROR_WRITE_PROTECT                     = 19
	ERROR_BAD_UNIT                          = 20
	ERROR_NOT_READY                         = 21
	ERROR_BAD_COMMAND                       = 22
	ERROR_CRC                               = 23
	ERROR_BAD_LENGTH                        = 24
	ERROR_SEEK                              = 25
	ERROR_NOT_DOS_DISK                      = 26
	ERROR_SECTOR_NOT_FOUND                  = 27
	ERROR_OUT_OF_PAPER                      = 28
	ERROR_WRITE_FAULT                       = 29
	ERROR_READ_FAULT                        = 30
	ERROR_GEN_FAILURE                       = 31
	ERROR_SHARING_VIOLATION                 = 32
	ERROR_LOCK_VIOLATION                    = 33
	ERROR_WRONG_DISK                        = 34
	ERROR_SHARING_BUFFER_EXCEEDED           = 36
	ERROR_HANDLE_EOF                        = 38
	ERROR_HANDLE_DISK_FULL                  = 39
	ERROR_NOT_SUPPORTED                     = 50
	ERROR_REM_NOT_LIST                      = 51
	ERROR_DUP_NAME                          = 52
	ERROR_BAD_NETPATH                       = 53
	ERROR_NETWORK_BUSY                      = 54
	ERROR_DEV_NOT_EXIST                     = 55
	ERROR_TOO_MANY_CMDS                     = 56
	ERROR_ADAP_HDW_ERR                      = 57
	ERROR_BAD_NET_RESP                      = 58
	ERROR_UNEXP_NET_ERR                     = 59
	ERROR_BAD_REM_ADAP                      = 60
	ERROR_PRINTQ_FULL                       = 61
	ERROR_NO_SPOOL_SPACE                    = 62
	ERROR_PRINT_CANCELLED                   = 63
	ERROR_NETNAME_DELETED                   = 64
	ERROR_NETWORK_ACCESS_DENIED             = 65
	ERROR_BAD_DEV_TYPE                      = 66
	ERROR_BAD_NET_NAME                      = 67
	ERROR_TOO_MANY_NAMES                    = 68
	ERROR_TOO_MANY_SESS                     = 69
	ERROR_SHARING_PAUSED                    = 70
	ERROR_REQ_NOT_ACCEP                     = 71
	ERROR_REDIR_PAUSED                      = 72
	ERROR_FILE_EXISTS                       = 80
	ERROR_CANNOT_MAKE                       = 82
	ERROR_FAIL_I24                          = 83
	ERROR_OUT_OF_STRUCTURES                 = 84
	ERROR_ALREADY_ASSIGNED                  = 85
	ERROR_INVALID_PASSWORD                  = 86
	ERROR_NET_WRITE_FAULT                   = 88
	ERROR_NO_PROC_SLOTS                     = 89
	ERROR_TOO_MANY_SEMAPHORES               = 100
	ERROR_EXCL_SEM_ALREADY_OWNED            = 101
	ERROR_SEM_IS_SET                        = 102
	ERROR_TOO_MANY_SEM_REQUESTS             = 103
	ERROR_INVALID_AT_INTERRUPT_TIME         = 104
	ERROR_SEM_OWNER_DIED                    = 105
	ERROR_SEM_USER_LIMIT                    = 106
	ERROR_DISK_CHANGE                       = 107
	ERROR_DRIVE_LOCKED                      = 108
	ERROR_BROKEN_PIPE                       = 109
	ERROR_OPEN_FAILED                       = 110
	ERROR_BUFFER_OVERFLOW                   = 111
	ERROR_DISK_FULL                         = 112
	ERROR_NO_MORE_SEARCH_HANDLES            = 113
	ERROR_INVALID_TARGET_HANDLE             = 114
	ERROR_INVALID_CATEGORY                  = 117
	ERROR_INVALID_VERIFY_SWITCH             = 118
	ERROR_BAD_DRIVER_LEVEL                  = 119
	ERROR_CALL_NOT_IMPLEMENTED              = 120
	ERROR_SEM_TIMEOUT                       = 121
	ERROR_INVALID_NAME                      = 123
	ERROR_INVALID_LEVEL                     = 124
	ERROR_NO_VOLUME_LABEL                   = 125
	ERROR_MOD_NOT_FOUND                     = 126
	ERROR_PROC_NOT_FOUND                    = 127
	ERROR_WAIT_NO_CHILDREN                  = 128
	ERROR_CHILD_NOT_COMPLETE                = 129
	ERROR_DIRECT_ACCESS_HANDLE              = 130
	ERROR_NEGATIVE_SEEK                     = 131
	ERROR_SEEK_ON_DEVICE                    = 132
	ERROR_IS_JOIN_TARGET                    = 133
	ERROR_IS_JOINED                         = 134
	ERROR_IS_SUBSTED                        = 135
	ERROR_NOT_JOINED                        = 136
	ERROR_NOT_SUBSTED                       = 137
	ERROR_JOIN_TO_JOIN                      = 138
	ERROR_SUBST_TO_SUBST                    = 139
	ERROR_JOIN_TO_SUBST                     = 140
	ERROR_SUBST_TO_JOIN                     = 141
	ERROR_BUSY_DRIVE                        = 142
	ERROR_SAME_DRIVE                        = 143
	ERROR_DIR_NOT_ROOT                      = 144
	ERROR_DIR_NOT_EMPTY                     = 145
	ERROR_IS_SUBST_PATH                     = 146
	ERROR_IS_JOIN_PATH                      = 147
	ERROR_PATH_BUSY                         = 148
	ERROR_IS_SUBST_TARGET                   = 149
	ERROR_SYSTEM_TRACE                      = 150
	ERROR_INVALID_EVENT_COUNT               = 151
	ERROR_TOO_MANY_MUXWAITERS               = 152
	ERROR_INVALID_LIST_FORMAT               = 153
	ERROR_LABEL_TOO_LONG                    = 154
	ERROR_TOO_MANY_TCBS                     = 155
	ERROR_SIGNAL_REFUSED                    = 156
	ERROR_DISCARDED                         = 157
	ERROR_NOT_LOCKED                        = 158
	ERROR_BAD_THREADID_ADDR                 = 159
	ERROR_BAD_ARGUMENTS                     = 160
	ERROR_BAD_PATHNAME                      = 161
	ERROR_SIGNAL_PENDING                    = 162
	ERROR_MAX_THRDS_REACHED                 = 164
	ERROR_LOCK_FAILED                       = 167
	ERROR_BUSY                              = 170
	ERROR_CANCEL_VIOLATION                  = 173
	ERROR_ATOMIC_LOCKS_NOT_SUPPORTED        = 174
	ERROR_INVALID_SEGMENT_NUMBER            = 180
	ERROR_INVALID_ORDINAL                   = 182
	ERROR_ALREADY_EXISTS                    = 183
	ERROR_INVALID_FLAG_NUMBER               = 186
	ERROR_SEM_NOT_FOUND                     = 187
	ERROR_INVALID_STARTING_CODESEG          = 188
	ERROR_INVALID_STACKSEG                  = 189
	ERROR_INVALID_MODULETYPE                = 190
	ERROR_INVALID_EXE_SIGNATURE             = 191
	ERROR_EXE_MARKED_INVALID                = 192
	ERROR_BAD_EXE_FORMAT                    = 193
	ERROR_ITERATED_DATA_EXCEEDS_64k         = 194
	ERROR_INVALID_MINALLOCSIZE              = 195
	ERROR_DYNLINK_FROM_INVALID_RING         = 196
	ERROR_IOPL_NOT_ENABLED                  = 197
	ERROR_INVALID_SEGDPL                    = 198
	ERROR_AUTODATASEG_EXCEEDS_64k           = 199
	ERROR_RING2SEG_MUST_BE_MOVABLE          = 200
	ERROR_RELOC_CHAIN_XEEDS_SEGLIM          = 201
	ERROR_INFLOOP_IN_RELOC_CHAIN            = 202
	ERROR_ENVVAR_NOT_FOUND                  = 203
	ERROR_NO_SIGNAL_SENT                    = 205
	ERROR_FILENAME_EXCED_RANGE              = 206
	ERROR_RING2_STACK_IN_USE                = 207
	ERROR_META_EXPANSION_TOO_LONG           = 208
	ERROR_INVALID_SIGNAL_NUMBER             = 209
	ERROR_THREAD_1_INACTIVE                 = 210
	ERROR_LOCKED                            = 212
	ERROR_TOO_MANY_MODULES                  = 214
	ERROR_NESTING_NOT_ALLOWED               = 215
	ERROR_BAD_PIPE                          = 230
	ERROR_PIPE_BUSY                         = 231
	ERROR_NO_DATA                           = 232
	ERROR_PIPE_NOT_CONNECTED                = 233
	ERROR_VC_DISCONNECTED                   = 240
	ERROR_INVALID_EA_NAME                   = 254
	ERROR_EA_LIST_INCONSISTENT              = 255
	ERROR_CANNOT_COPY                       = 266
	ERROR_DIRECTORY                         = 267
	ERROR_EAS_DIDNT_FIT                     = 275
	ERROR_EA_FILE_CORRUPT                   = 276
	ERROR_EA_TABLE_FULL                     = 277
	ERROR_INVALID_EA_HANDLE                 = 278
	ERROR_EAS_NOT_SUPPORTED                 = 282
	ERROR_NOT_OWNER                         = 288
	ERROR_TOO_MANY_POSTS                    = 298
	ERROR_PARTIAL_COPY                      = 299
	ERROR_MR_MID_NOT_FOUND                  = 317
	ERROR_INVALID_ADDRESS                   = 487
	ERROR_ARITHMETIC_OVERFLOW               = 534
	ERROR_PIPE_CONNECTED                    = 535
	ERROR_PIPE_LISTENING                    = 536
	ERROR_EA_ACCESS_DENIED                  = 994
	ERROR_OPERATION_ABORTED                 = 995
	ERROR_IO_INCOMPLETE                     = 996
	ERROR_IO_PENDING                        = 997
	ERROR_NOACCESS                          = 998
	ERROR_SWAPERROR                         = 999
	ERROR_STACK_OVERFLOW                    = 1001
	ERROR_INVALID_MESSAGE                   = 1002
	ERROR_CAN_NOT_COMPLETE                  = 1003
	ERROR_INVALID_FLAGS                     = 1004
	ERROR_UNRECOGNIZED_VOLUME               = 1005
	ERROR_FILE_INVALID                      = 1006
	ERROR_FULLSCREEN_MODE                   = 1007
	ERROR_NO_TOKEN                          = 1008
	ERROR_BADDB                             = 1009
	ERROR_BADKEY                            = 1010
	ERROR_CANTOPEN                          = 1011
	ERROR_CANTREAD                          = 1012
	ERROR_CANTWRITE                         = 1013
	ERROR_REGISTRY_RECOVERED                = 1014
	ERROR_REGISTRY_CORRUPT                  = 1015
	ERROR_REGISTRY_IO_FAILED                = 1016
	ERROR_NOT_REGISTRY_FILE                 = 1017
	ERROR_KEY_DELETED                       = 1018
	ERROR_NO_LOG_SPACE                      = 1019
	ERROR_KEY_HAS_CHILDREN                  = 1020
	ERROR_CHILD_MUST_BE_VOLATILE            = 1021
	ERROR_NOTIFY_ENUM_DIR                   = 1022
	ERROR_DEPENDENT_SERVICES_RUNNING        = 1051
	ERROR_INVALID_SERVICE_CONTROL           = 1052
	ERROR_SERVICE_REQUEST_TIMEOUT           = 1053
	ERROR_SERVICE_NO_THREAD                 = 1054
	ERROR_SERVICE_DATABASE_LOCKED           = 1055
	ERROR_SERVICE_ALREADY_RUNNING           = 1056
	ERROR_INVALID_SERVICE_ACCOUNT           = 1057
	ERROR_SERVICE_DISABLED                  = 1058
	ERROR_CIRCULAR_DEPENDENCY               = 1059
	ERROR_SERVICE_DOES_NOT_EXIST            = 1060
	ERROR_SERVICE_CANNOT_ACCEPT_CTRL        = 1061
	ERROR_SERVICE_NOT_ACTIVE                = 1062
	ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
	ERROR_EXCEPTION_IN_SERVICE              = 1064
	ERROR_DATABASE_DOES_NOT_EXIST           = 1065
	ERROR_SERVICE_SPECIFIC_ERROR            = 1066
	ERROR_PROCESS_ABORTED                   = 1067
	ERROR_SERVICE_DEPENDENCY_FAIL           = 1068
	ERROR_SERVICE_LOGON_FAILED              = 1069
	ERROR_SERVICE_START_HANG                = 1070
	ERROR_INVALID_SERVICE_LOCK              = 1071
	ERROR_SERVICE_MARKED_FOR_DELETE         = 1072
	ERROR_SERVICE_EXISTS                    = 1073
	ERROR_ALREADY_RUNNING_LKG               = 1074
	ERROR_SERVICE_DEPENDENCY_DELETED        = 1075
	ERROR_BOOT_ALREADY_ACCEPTED             = 1076
	ERROR_SERVICE_NEVER_STARTED             = 1077
	ERROR_DUPLICATE_SERVICE_NAME            = 1078
	ERROR_END_OF_MEDIA                      = 1100
	ERROR_FILEMARK_DETECTED                 = 1101
	ERROR_BEGINNING_OF_MEDIA                = 1102
	ERROR_SETMARK_DETECTED                  = 1103
	ERROR_NO_DATA_DETECTED                  = 1104
	ERROR_PARTITION_FAILURE                 = 1105
	ERROR_INVALID_BLOCK_LENGTH              = 1106
	ERROR_DEVICE_NOT_PARTITIONED            = 1107
	ERROR_UNABLE_TO_LOCK_MEDIA              = 1108
	ERROR_UNABLE_TO_UNLOAD_MEDIA            = 1109
	ERROR_MEDIA_CHANGED                     = 1110
	ERROR_BUS_RESET                         = 1111
	ERROR_NO_MEDIA_IN_DRIVE                 = 1112
	ERROR_NO_UNICODE_TRANSLATION            = 1113
	ERROR_DLL_INIT_FAILED                   = 1114
	ERROR_SHUTDOWN_IN_PROGRESS              = 1115
	ERROR_NO_SHUTDOWN_IN_PROGRESS           = 1116
	ERROR_IO_DEVICE                         = 1117
	ERROR_SERIAL_NO_DEVICE                  = 1118
	ERROR_IRQ_BUSY                          = 1119
	ERROR_MORE_WRITES                       = 1120
	ERROR_COUNTER_TIMEOUT                   = 1121
	ERROR_FLOPPY_ID_MARK_NOT_FOUND          = 1122
	ERROR_FLOPPY_WRONG_CYLINDER             = 1123
	ERROR_FLOPPY_UNKNOWN_ERROR              = 1124
	ERROR_FLOPPY_BAD_REGISTERS              = 1125
	ERROR_DISK_RECALIBRATE_FAILED           = 1126
	ERROR_DISK_OPERATION_FAILED             = 1127
	ERROR_DISK_RESET_FAILED                 = 1128
	ERROR_EOM_OVERFLOW                      = 1129
	ERROR_NOT_ENOUGH_SERVER_MEMORY          = 1130
	ERROR_POSSIBLE_DEADLOCK                 = 1131
	ERROR_MAPPED_ALIGNMENT                  = 1132
	ERROR_SET_POWER_STATE_VETOED            = 1140
	ERROR_SET_POWER_STATE_FAILED            = 1141
	ERROR_TOO_MANY_LINKS                    = 1142
	ERROR_OLD_WIN_VERSION                   = 1150
	ERROR_APP_WRONG_OS                      = 1151
	ERROR_SINGLE_INSTANCE_APP               = 1152
	ERROR_RMODE_APP                         = 1153
	ERROR_INVALID_DLL                       = 1154
	ERROR_NO_ASSOCIATION                    = 1155
	ERROR_DDE_FAIL                          = 1156
	ERROR_DLL_NOT_FOUND                     = 1157
	ERROR_BAD_USERNAME                      = 2202
	ERROR_NOT_CONNECTED                     = 2250
	ERROR_OPEN_FILES                        = 2401
	ERROR_ACTIVE_CONNECTIONS                = 2402
	ERROR_DEVICE_IN_USE                     = 2404
	ERROR_BAD_DEVICE                        = 1200
	ERROR_CONNECTION_UNAVAIL                = 1201
	ERROR_DEVICE_ALREADY_REMEMBERED         = 1202
	ERROR_NO_NET_OR_BAD_PATH                = 1203
	ERROR_BAD_PROVIDER                      = 1204
	ERROR_CANNOT_OPEN_PROFILE               = 1205
	ERROR_BAD_PROFILE                       = 1206
	ERROR_NOT_CONTAINER                     = 1207
	ERROR_EXTENDED_ERROR                    = 1208
	ERROR_INVALID_GROUPNAME                 = 1209
	ERROR_INVALID_COMPUTERNAME              = 1210
	ERROR_INVALID_EVENTNAME                 = 1211
	ERROR_INVALID_DOMAINNAME                = 1212
	ERROR_INVALID_SERVICENAME               = 1213
	ERROR_INVALID_NETNAME                   = 1214
	ERROR_INVALID_SHARENAME                 = 1215
	ERROR_INVALID_PASSWORDNAME              = 1216
	ERROR_INVALID_MESSAGENAME               = 1217
	ERROR_INVALID_MESSAGEDEST               = 1218
	ERROR_SESSION_CREDENTIAL_CONFLICT       = 1219
	ERROR_REMOTE_SESSION_LIMIT_EXCEEDED     = 1220
	ERROR_DUP_DOMAINNAME                    = 1221
	ERROR_NO_NETWORK                        = 1222
	ERROR_CANCELLED                         = 1223
	ERROR_USER_MAPPED_FILE                  = 1224
	ERROR_CONNECTION_REFUSED                = 1225
	ERROR_GRACEFUL_DISCONNECT               = 1226
	ERROR_ADDRESS_ALREADY_ASSOCIATED        = 1227
	ERROR_ADDRESS_NOT_ASSOCIATED            = 1228
	ERROR_CONNECTION_INVALID                = 1229
	ERROR_CONNECTION_ACTIVE                 = 1230
	ERROR_NETWORK_UNREACHABLE               = 1231
	ERROR_HOST_UNREACHABLE                  = 1232
	ERROR_PROTOCOL_UNREACHABLE              = 1233
	ERROR_PORT_UNREACHABLE                  = 1234
	ERROR_REQUEST_ABORTED                   = 1235
	ERROR_CONNECTION_ABORTED                = 1236
	ERROR_RETRY                             = 1237
	ERROR_CONNECTION_COUNT_LIMIT            = 1238
	ERROR_LOGIN_TIME_RESTRICTION            = 1239
	ERROR_LOGIN_WKSTA_RESTRICTION           = 1240
	ERROR_INCORRECT_ADDRESS                 = 1241
	ERROR_ALREADY_REGISTERED                = 1242
	ERROR_SERVICE_NOT_FOUND                 = 1243
	ERROR_NOT_AUTHENTICATED                 = 1244
	ERROR_NOT_LOGGED_ON                     = 1245
	ERROR_CONTINUE                          = 1246
	ERROR_ALREADY_INITIALIZED               = 1247
	ERROR_NO_MORE_DEVICES                   = 1248
	ERROR_NOT_ALL_ASSIGNED                  = 1300
	ERROR_SOME_NOT_MAPPED                   = 1301
	ERROR_NO_QUOTAS_FOR_ACCOUNT             = 1302
	ERROR_LOCAL_USER_SESSION_KEY            = 1303
	ERROR_NULL_LM_PASSWORD                  = 1304
	ERROR_UNKNOWN_REVISION                  = 1305
	ERROR_REVISION_MISMATCH                 = 1306
	ERROR_INVALID_OWNER                     = 1307
	ERROR_INVALID_PRIMARY_GROUP             = 1308
	ERROR_NO_IMPERSONATION_TOKEN            = 1309
	ERROR_CANT_DISABLE_MANDATORY            = 1310
	ERROR_NO_LOGON_SERVERS                  = 1311
	ERROR_NO_SUCH_LOGON_SESSION             = 1312
	ERROR_NO_SUCH_PRIVILEGE                 = 1313
	ERROR_PRIVILEGE_NOT_HELD                = 1314
	ERROR_INVALID_ACCOUNT_NAME              = 1315
	ERROR_USER_EXISTS                       = 1316
	ERROR_NO_SUCH_USER                      = 1317
	ERROR_GROUP_EXISTS                      = 1318
	ERROR_NO_SUCH_GROUP                     = 1319
	ERROR_MEMBER_IN_GROUP                   = 1320
	ERROR_MEMBER_NOT_IN_GROUP               = 1321
	ERROR_LAST_ADMIN                        = 1322
	ERROR_WRONG_PASSWORD                    = 1323
	ERROR_ILL_FORMED_PASSWORD               = 1324
	ERROR_PASSWORD_RESTRICTION              = 1325
	ERROR_LOGON_FAILURE                     = 1326
	ERROR_ACCOUNT_RESTRICTION               = 1327
	ERROR_INVALID_LOGON_HOURS               = 1328
	ERROR_INVALID_WORKSTATION               = 1329
	ERROR_PASSWORD_EXPIRED                  = 1330
	ERROR_ACCOUNT_DISABLED                  = 1331
	ERROR_NONE_MAPPED                       = 1332
	ERROR_TOO_MANY_LUIDS_REQUESTED          = 1333
	ERROR_LUIDS_EXHAUSTED                   = 1334
	ERROR_INVALID_SUB_AUTHORITY             = 1335
	ERROR_INVALID_ACL                       = 1336
	ERROR_INVALID_SID                       = 1337
	ERROR_INVALID_SECURITY_DESCR            = 1338
	ERROR_BAD_INHERITANCE_ACL               = 1340
	ERROR_SERVER_DISABLED                   = 1341
	ERROR_SERVER_NOT_DISABLED               = 1342
	ERROR_INVALID_ID_AUTHORITY              = 1343
	ERROR_ALLOTTED_SPACE_EXCEEDED           = 1344
	ERROR_INVALID_GROUP_ATTRIBUTES          = 1345
	ERROR_BAD_IMPERSONATION_LEVEL           = 1346
	ERROR_CANT_OPEN_ANONYMOUS               = 1347
	ERROR_BAD_VALIDATION_CLASS              = 1348
	ERROR_BAD_TOKEN_TYPE                    = 1349
	ERROR_NO_SECURITY_ON_OBJECT             = 1350
	ERROR_CANT_ACCESS_DOMAIN_INFO           = 1351
	ERROR_INVALID_SERVER_STATE              = 1352
	ERROR_INVALID_DOMAIN_STATE              = 1353
	ERROR_INVALID_DOMAIN_ROLE               = 1354
	ERROR_NO_SUCH_DOMAIN                    = 1355
	ERROR_DOMAIN_EXISTS                     = 1356
	ERROR_DOMAIN_LIMIT_EXCEEDED             = 1357
	ERROR_INTERNAL_DB_CORRUPTION            = 1358
	ERROR_INTERNAL_ERROR                    = 1359
	ERROR_GENERIC_NOT_MAPPED                = 1360
	ERROR_BAD_DESCRIPTOR_FORMAT             = 1361
	ERROR_NOT_LOGON_PROCESS                 = 1362
	ERROR_LOGON_SESSION_EXISTS              = 1363
	ERROR_NO_SUCH_PACKAGE                   = 1364
	ERROR_BAD_LOGON_SESSION_STATE           = 1365
	ERROR_LOGON_SESSION_COLLISION           = 1366
	ERROR_INVALID_LOGON_TYPE                = 1367
	ERROR_CANNOT_IMPERSONATE                = 1368
	ERROR_RXACT_INVALID_STATE               = 1369
	ERROR_RXACT_COMMIT_FAILURE              = 1370
	ERROR_SPECIAL_ACCOUNT                   = 1371
	ERROR_SPECIAL_GROUP                     = 1372
	ERROR_SPECIAL_USER                      = 1373
	ERROR_MEMBERS_PRIMARY_GROUP             = 1374
	ERROR_TOKEN_ALREADY_IN_USE              = 1375
	ERROR_NO_SUCH_ALIAS                     = 1376
	ERROR_MEMBER_NOT_IN_ALIAS               = 1377
	ERROR_MEMBER_IN_ALIAS                   = 1378
	ERROR_ALIAS_EXISTS                      = 1379
	ERROR_LOGON_NOT_GRANTED                 = 1380
	ERROR_TOO_MANY_SECRETS                  = 1381
	ERROR_SECRET_TOO_LONG                   = 1382
	ERROR_INTERNAL_DB_ERROR                 = 1383
	ERROR_TOO_MANY_CONTEXT_IDS              = 1384
	ERROR_LOGON_TYPE_NOT_GRANTED            = 1385
	ERROR_NT_CROSS_ENCRYPTION_REQUIRED      = 1386
	ERROR_NO_SUCH_MEMBER                    = 1387
	ERROR_INVALID_MEMBER                    = 1388
	ERROR_TOO_MANY_SIDS                     = 1389
	ERROR_LM_CROSS_ENCRYPTION_REQUIRED      = 1390
	ERROR_NO_INHERITANCE                    = 1391
	ERROR_FILE_CORRUPT                      = 1392
	ERROR_DISK_CORRUPT                      = 1393
	ERROR_NO_USER_SESSION_KEY               = 1394
	ERROR_LICENSE_QUOTA_EXCEEDED            = 1395
	ERROR_INVALID_WINDOW_HANDLE             = 1400
	ERROR_INVALID_MENU_HANDLE               = 1401
	ERROR_INVALID_CURSOR_HANDLE             = 1402
	ERROR_INVALID_ACCEL_HANDLE              = 1403
	ERROR_INVALID_HOOK_HANDLE               = 1404
	ERROR_INVALID_DWP_HANDLE                = 1405
	ERROR_TLW_WITH_WSCHILD                  = 1406
	ERROR_CANNOT_FIND_WND_CLASS             = 1407
	ERROR_WINDOW_OF_OTHER_THREAD            = 1408
	ERROR_HOTKEY_ALREADY_REGISTERED         = 1409
	ERROR_CLASS_ALREADY_EXISTS              = 1410
	ERROR_CLASS_DOES_NOT_EXIST              = 1411
	ERROR_CLASS_HAS_WINDOWS                 = 1412
	ERROR_INVALID_INDEX                     = 1413
	ERROR_INVALID_ICON_HANDLE               = 1414
	ERROR_PRIVATE_DIALOG_INDEX              = 1415
	ERROR_LISTBOX_ID_NOT_FOUND              = 1416
	ERROR_NO_WILDCARD_CHARACTERS            = 1417
	ERROR_CLIPBOARD_NOT_OPEN                = 1418
	ERROR_HOTKEY_NOT_REGISTERED             = 1419
	ERROR_WINDOW_NOT_DIALOG                 = 1420
	ERROR_CONTROL_ID_NOT_FOUND              = 1421
	ERROR_INVALID_COMBOBOX_MESSAGE          = 1422
	ERROR_WINDOW_NOT_COMBOBOX               = 1423
	ERROR_INVALID_EDIT_HEIGHT               = 1424
	ERROR_DC_NOT_FOUND                      = 1425
	ERROR_INVALID_HOOK_FILTER               = 1426
	ERROR_INVALID_FILTER_PROC               = 1427
	ERROR_HOOK_NEEDS_HMOD                   = 1428
	ERROR_GLOBAL_ONLY_HOOK                  = 1429
	ERROR_JOURNAL_HOOK_SET                  = 1430
	ERROR_HOOK_NOT_INSTALLED                = 1431
	ERROR_INVALID_LB_MESSAGE                = 1432
	ERROR_SETCOUNT_ON_BAD_LB                = 1433
	ERROR_LB_WITHOUT_TABSTOPS               = 1434
	ERROR_DESTROY_OBJECT_OF_OTHER_THREAD    = 1435
	ERROR_CHILD_WINDOW_MENU                 = 1436
	ERROR_NO_SYSTEM_MENU                    = 1437
	ERROR_INVALID_MSGBOX_STYLE              = 1438
	ERROR_INVALID_SPI_VALUE                 = 1439
	ERROR_SCREEN_ALREADY_LOCKED             = 1440
	ERROR_HWNDS_HAVE_DIFF_PARENT            = 1441
	ERROR_NOT_CHILD_WINDOW                  = 1442
	ERROR_INVALID_GW_COMMAND                = 1443
	ERROR_INVALID_THREAD_ID                 = 1444
	ERROR_NON_MDICHILD_WINDOW               = 1445
	ERROR_POPUP_ALREADY_ACTIVE              = 1446
	ERROR_NO_SCROLLBARS                     = 1447
	ERROR_INVALID_SCROLLBAR_RANGE           = 1448
	ERROR_INVALID_SHOWWIN_COMMAND           = 1449
	ERROR_NO_SYSTEM_RESOURCES               = 1450
	ERROR_NONPAGED_SYSTEM_RESOURCES         = 1451
	ERROR_PAGED_SYSTEM_RESOURCES            = 1452
	ERROR_WORKING_SET_QUOTA                 = 1453
	ERROR_PAGEFILE_QUOTA                    = 1454
	ERROR_COMMITMENT_LIMIT                  = 1455
	ERROR_MENU_ITEM_NOT_FOUND               = 1456
	ERROR_EVENTLOG_FILE_CORRUPT             = 1500
	ERROR_EVENTLOG_CANT_START               = 1501
	ERROR_LOG_FILE_FULL                     = 1502
	ERROR_EVENTLOG_FILE_CHANGED             = 1503
)

func SUCCEEDED(hr HRESULT) bool {
	return hr >= 0
}

func FAILED(hr HRESULT) bool {
	return hr < 0
}

func MAKEWORD(lo, hi byte) uint16 {
	return uint16(uint16(lo) | ((uint16(hi)) << 8))
}

func LOBYTE(w uint16) byte {
	return byte(w)
}

func HIBYTE(w uint16) byte {
	return byte(w >> 8 & 0xff)
}

func MAKELONG(lo, hi uint16) uint32 {
	return uint32(uint32(lo) | ((uint32(hi)) << 16))
}

func LOWORD(dw uint32) uint16 {
	return uint16(dw)
}

func HIWORD(dw uint32) uint16 {
	return uint16(dw >> 16 & 0xffff)
}

func UTF16PtrToString(s *uint16) string {
	if s == nil {
		return ""
	}
	return syscall.UTF16ToString((*[1 << 29]uint16)(unsafe.Pointer(s))[0:])
}

func MAKEINTRESOURCE(id uintptr) *uint16 {
	return (*uint16)(unsafe.Pointer(id))
}

func BoolToBOOL(value bool) BOOL {
	if value {
		return 1
	}

	return 0
}

func UTF16PtrFromString(str *string) *uint16 {
	if str == nil {
		return nil
	}

	result, _ := syscall.UTF16PtrFromString(*str)

	return result
}
