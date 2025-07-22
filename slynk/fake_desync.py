import socket
import time
import platform
import threading

from .config import CONFIG
from .utils import set_ttl, to_thread
from .logger_with_context import logger, policy_ctx
from . import remote

logger = logger.getChild("fake_desync")
system = platform.system()
semaphore = threading.Semaphore(CONFIG.get('TransmitFileLimit') or 2)

if system == "Windows":

    import ctypes
    from ctypes import wintypes

    # 加载 mswsock.dll 库
    mswsock = ctypes.WinDLL("mswsock")
    # 加载 ws2_32.dll 库
    ws2_32 = ctypes.windll.ws2_32
    # 加载 kernel32.dll 库
    kernel32 = ctypes.windll.kernel32
    msvcrt = ctypes.cdll.msvcrt

    class _DUMMYSTRUCTNAME(ctypes.Structure):
        _fields_ = [
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
        ]

    # 定义 TransmitFile 函数的参数类型
    class _DUMMYUNIONNAME(ctypes.Union):
        _fields_ = [
            ("Pointer", ctypes.POINTER(ctypes.c_void_p)),
            ("DUMMYSTRUCTNAME", _DUMMYSTRUCTNAME),
        ]

    # class OVERLAPPED(ctypes.Structure):
    #     _fields_ = [
    #         ("Internal", wintypes.ULONG),
    #         ("InternalHigh", wintypes.ULONG),
    #         ("DUMMYUNIONNAME", _DUMMYUNIONNAME),
    #         ("hEvent", wintypes.HANDLE),
    #     ]

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", ctypes.c_ulong),
            ("OffsetHigh", ctypes.c_ulong),
            ("hEvent", ctypes.c_void_p),
        ]

    # import pywintypes
    mswsock.TransmitFile.argtypes = [
        wintypes.HANDLE,  # 套接字句柄
        wintypes.HANDLE,  # 文件句柄
        wintypes.DWORD,  # 要发送的字节数
        wintypes.DWORD,  # 每次发送的字节数
        ctypes.POINTER(OVERLAPPED),  # 重叠结构指针
        ctypes.POINTER(ctypes.c_void_p),  # 传输缓冲区指针
        wintypes.DWORD,  # 保留参数
    ]
    # 定义 TransmitFile 函数的返回值类型
    mswsock.TransmitFile.restype = wintypes.BOOL
    # ws2_32.WSASocketW.argtypes = [
    #     wintypes.INT, wintypes.INT, wintypes.INT,
    #     wintypes.DWORD,wintypes.DWORD, wintypes.DWORD
    # ]
    # ws2_32.WSASocketW.restype = ctypes.c_uint

    kernel32.CreateFileA.argtypes = [
        wintypes.LPCSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    kernel32.CreateFileA.restype = wintypes.HANDLE
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.SetFilePointer.argtypes = [
        wintypes.HANDLE,
        ctypes.c_long,
        wintypes.LONG,
        wintypes.DWORD,
    ]
    kernel32.SetFilePointer.restype = ctypes.c_long
    kernel32.SetEndOfFile.argtypes = [wintypes.HANDLE]
    kernel32.SetEndOfFile.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    msvcrt._get_osfhandle.argtypes = [wintypes.INT]
    msvcrt._get_osfhandle.restype = wintypes.HANDLE
    # kernel32._get_osfhandle.argtypes = [wintypes.INT]
    # kernel32._get_osfhandle.restype = wintypes.HANDLE

    semaphore = threading.Semaphore(CONFIG.get('TransmitFileLimit') or 2)

    def send_fake_data(
        data_len,
        fake_data,
        fake_ttl,
        real_data,
        default_ttl,
        sock,
        FAKE_sleep
    ):
        import tempfile, uuid, os
        logger.warning(
            "Desync on Windows may cause Error! "
            "Make sure other programs are not using the TransmitFile."
        )
        """
        BOOL TransmitFile(
            SOCKET                  hSocket,
            HANDLE                  hFile,
            DWORD                   nNumberOfBytesToWrite,
            DWORD                   nNumberOfBytesPerSend,
            LPOVERLAPPED            lpOverlapped,
            LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
            DWORD                   dwReserved
        );
        """
        file_path = f"{tempfile.gettempdir()}\\{uuid.uuid4()}.txt"

        sock_file_descriptor = sock.fileno()
        logger.debug("Sock file discriptor: %s", sock_file_descriptor)
        file_handle = kernel32.CreateFileA(
            bytes(file_path, encoding="utf-8"),
            wintypes.DWORD(0x40000000 | 0x80000000),
            # GENERIC_READ | GENERIC_WRITE
            wintypes.DWORD(0x00000001 | 0x00000002),
            # FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            wintypes.DWORD(2),  # CREATE_ALWAYS
            # 0,
            0x00000100,  # FILE_FLAG_DELETE_ON_CLOSE
            None
        )

        if file_handle == -1:
            logger.error(
                "Failed to create file. Error code: %s",
                kernel32.GetLastError()
            )
            return False
        logger.debug(
            "Created file successfully. file_handle=%s", file_handle)
        try:
            ov = OVERLAPPED()
            ov.hEvent = kernel32.CreateEventA(None, True, False, None)
            if ov.hEvent <= 0:
                logger.error(
                    "Failed to create event. Error code: %s",
                    kernel32.GetLastError()
                )
                return False
            logger.info("Successfully create event. ov.hEvent=%s", ov.hEvent)

            kernel32.SetFilePointer(file_handle, 0, 0, 0)
            kernel32.WriteFile(
                file_handle,
                fake_data,
                data_len,
                ctypes.byref(wintypes.DWORD(0)),
                None,
            )
            kernel32.SetEndOfFile(file_handle)
            set_ttl(sock, fake_ttl)
            kernel32.SetFilePointer(file_handle, 0, 0, 0)

            logger.debug("%s %s %s", fake_data, real_data, data_len)

            with semaphore:
                result = mswsock.TransmitFile(
                    sock_file_descriptor,
                    file_handle,
                    wintypes.DWORD(data_len),
                    wintypes.DWORD(data_len),
                    ov,
                    None,
                    32 | 4,  # TF_USE_KERNEL_APC | TF_WRITE_BEHIND
                )

                if FAKE_sleep < 0.1:
                    logger.warning(
                        "Too short sleep time on Windows, set to 0.1")
                    FAKE_sleep = 0.1

                logger.debug("Sleep for: %s", FAKE_sleep)
                time.sleep(FAKE_sleep)
                kernel32.SetFilePointer(file_handle, 0, 0, 0)
                kernel32.WriteFile(
                    file_handle,
                    real_data,
                    data_len,
                    ctypes.byref(wintypes.DWORD(0)),
                    None,
                )
                kernel32.SetEndOfFile(file_handle)
                kernel32.SetFilePointer(file_handle, 0, 0, 0)
                set_ttl(sock, default_ttl)

                val = kernel32.WaitForSingleObject(
                    ov.hEvent, wintypes.DWORD(5000))

            if val == 0:
                logger.info("TransmitFile call was successful. %s", result)
                return True
            else:
                logger.error(
                    'TransmitFile call failed (on waiting for event). '
                    'Error code: %s %s',
                    kernel32.GetLastError(),
                    ws2_32.WSAGetLastError(),
                )
                return False
        except Exception as e:
            logger.error(
                "TransmitFile call failed due to %s. Error code: %s",
                repr(e),
                kernel32.GetLastError()
            )
            return False
        finally:
            kernel32.CloseHandle(file_handle)
            kernel32.CloseHandle(ov.hEvent)
            os.remove(file_path)

elif system in ("Linux", "Darwin", "Android"):
    import ctypes

    try:
        libc = ctypes.CDLL("libc.so.6")
    except Exception:
        libc = ctypes.CDLL("/system/lib64/libc.so")

    class iovec(ctypes.Structure):
        _fields_ = [
            ("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

    # 定义 splice 函数的参数类型和返回类型
    libc.splice.argtypes = [
        ctypes.c_int,  # int fd_in
        ctypes.c_longlong,  # loff_t *off_in
        ctypes.c_int,  # int fd_out
        ctypes.c_longlong,  # loff_t *off_out
        ctypes.c_size_t,  # size_t len
        ctypes.c_uint,  # unsigned int flags
    ]
    libc.splice.restype = ctypes.c_ssize_t

    # 定义 vmsplice 函数的参数类型和返回类型
    libc.vmsplice.argtypes = [
        ctypes.c_int,  # int fd
        ctypes.POINTER(iovec),  # struct iovec *iov
        ctypes.c_size_t,  # size_t nr_segs
        ctypes.c_uint,  # unsigned int flags
    ]
    libc.vmsplice.restype = ctypes.c_ssize_t

    libc.mmap.argtypes = [
        ctypes.c_void_p,  # void *addr
        ctypes.c_size_t,  # size_t length
        ctypes.c_int,  # int prot
        ctypes.c_int,  # int flags
        ctypes.c_int,  # int fd
        ctypes.c_size_t,  # off_t offset
    ]
    libc.mmap.restype = ctypes.c_void_p

    libc.memcpy.argtypes = [
        ctypes.c_void_p,  # void *dest
        ctypes.c_void_p,  # const void *src
        ctypes.c_size_t,  # size_t n
    ]
    libc.memcpy.restype = ctypes.c_void_p
    libc.close.argtypes = [ctypes.c_int]
    libc.close.restype = ctypes.c_int

    libc.munmap.argtypes = [
        ctypes.c_void_p,  # void *addr
        ctypes.c_size_t,  # size_t length
    ]
    libc.munmap.restype = ctypes.c_int

    libc.pipe.argtypes = [ctypes.POINTER(ctypes.c_int)]
    libc.pipe.restype = ctypes.c_int

    def send_fake_data(
        data_len,
        fake_data,
        fake_ttl,
        real_data,
        default_ttl,
        sock,
        FAKE_sleep
    ):
        try:
            sock_file_descriptor = sock.fileno()
            logger.debug("Sock file discriptor: %s", sock_file_descriptor)
            fds = (ctypes.c_int * 2)()
            if libc.pipe(fds) < 0:
                raise Exception("Failed to create pipe")
            logger.debug("Successfullly create pipe. %d %d", fds[0], fds[1])
            p = libc.mmap(
                0, ((data_len - 1) // 4 + 1) * 4, 0x1 | 0x2, 0x2 | 0x20, 0, 0
            )  # PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS
            if p == ctypes.c_void_p(-1):
                raise Exception("mmap failed")
            logger.debug("mmap success %s", p)
            libc.memcpy(p, fake_data, data_len)
            set_ttl(sock, fake_ttl)
            vec = iovec(p, data_len)
            len = libc.vmsplice(fds[1], ctypes.byref(vec), 1, 2) # SPLICE_F_GIFT
            if len < 0:
                raise Exception("vmsplice failed")
            logger.debug("vmsplice success %d", len)
            len = libc.splice(fds[0], 0, sock_file_descriptor, 0, data_len, 0)
            if len < 0:
                raise Exception("splice failed")
            logger.debug("splice success %d", len)
            logger.debug("Sleep for %s seconds.", FAKE_sleep)
            time.sleep(FAKE_sleep)
            libc.memcpy(p, real_data, data_len)
            set_ttl(sock, default_ttl)
        finally:
            libc.munmap(p, ((data_len - 1) // 4 + 1) * 4)
            libc.close(fds[0])
            libc.close(fds[1])
else:
    logger.error('Unsupported OS: %s', system)

async def send_data_with_fake(writer, data: bytes, sni: bytes):
    try:
        if (sock := writer.get_extra_info('socket')) is None:
            raise RuntimeError('Failed to get socket of writer')
        policy = policy_ctx.get()
        logger.debug("To send: %d bytes. ", len(data))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        default_ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        try:
            fake_data = policy.get("fake_packet")
            fake_ttl = policy.get("fake_ttl")
        except Exception:
            raise RuntimeError(
                "FAKE_packet or FAKE_ttl not set in settings.json",
                fake_data, fake_ttl
            )

        data_len = len(fake_data)
        FAKE_sleep = policy.get("fake_sleep")
        if await to_thread(
            send_fake_data,
            data_len,
            fake_data,
            fake_ttl,
            data[:data_len],
            default_ttl,
            sock,
            FAKE_sleep
        ):
            logger.debug("Fake data sent.")
        else:
            raise RuntimeError("Failed to send fake data.")

        data = data[data_len:]
        position = data.find(sni)
        logger.debug(f"{sni} {position}")
        if position == -1:
            writer.write(data)
            await writer.drain()
            return
        sni_len = len(sni)

        writer.write(data[:position])
        await writer.drain()
        data = data[position:]

        if policy.get("len_tcp_sni") >= sni_len:
            policy["len_tcp_sni"] = sni_len // 2
            logger.warning(
                "len_tcp_sni too big, set to %d", policy.get("len_tcp_sni")
            )

        if await to_thread(
            send_fake_data,
            policy.get("len_tcp_sni"),
            fake_data,
            fake_ttl,
            sni[:policy.get("len_tcp_sni")],
            default_ttl,
            sock,
            FAKE_sleep
        ):
            logger.debug("Fake sni sent.")
        else:
            raise RuntimeError("Failed to send fake SNI.")

        data = data[policy.get("len_tcp_sni"):]
        writer.write(data)
        await writer.drain()
        logger.info('ClientHello is sent in its entirety.')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)

    except Exception as e:
        logger.error(repr(e), exc_info=True)
