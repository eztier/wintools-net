﻿using System;
using System.IO;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace wintools {
  unsafe public class UnmanagedEncryption : IDisposable {
    bool disposed = false;
    public void Dispose() {
      if (!disposed) {
        Dispose(true);
        GC.SuppressFinalize(this);
      }
    }

    ~UnmanagedEncryption() {
      Dispose(false);
    }

    public virtual void Dispose(bool disposing) {
      if (disposing) {
        UnloadDllWrapper();
      }
    }
    
    static OperatingSystem os = Environment.OSVersion;
    string privateKey = null;
    string sharedSecret = null;

    // Remove access to default constructor.
    private UnmanagedEncryption() { }

    public UnmanagedEncryption(string privateKey_, string sharedSecret_) {
      privateKey = privateKey_;
      sharedSecret = sharedSecret_;
      CreateDynamicDllWrapper();
    }

    public string GetLastError { get; private set; }

    internal class NativeMethods {
      [DllImport("kernel32.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
      public static extern IntPtr LoadLibrary(string dllToLoad);

      [DllImport("kernel32.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
      public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

      [DllImport("kernel32.dll")]
      public static extern bool FreeLibrary(IntPtr hModule);

      [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
      public static extern IntPtr MemCopy(IntPtr dest, IntPtr src, uint count);
      
      [DllImport("libdl.so")]
      public static extern IntPtr dlopen(string filename, int flags);

      [DllImport("libdl.so")]
      public static extern bool dlclose(IntPtr handle);

      [DllImport("libdl.so")]
      public static extern IntPtr dlsym(IntPtr handle, string symbol);

      [DllImport("libdl.so")]
      public static extern IntPtr dlerror();
    }

    IntPtr dll_pointer = IntPtr.Zero;
    IntPtr decrypt_file_x_ptr = IntPtr.Zero;

    public static string executingDirectory = AppDomain.CurrentDomain.RelativeSearchPath ?? AppDomain.CurrentDomain.BaseDirectory;
    static bool isUnix = (os.Platform == PlatformID.Unix);
    static string filePrefix = !isUnix ? "\\" : "";
    string unmanagedDll = executingDirectory + filePrefix + "tinycrypto.dll";
    string unmanagedDll_so = executingDirectory + filePrefix + "tinycrypto.so";
    string libeay32_dll = executingDirectory + filePrefix + "libeay32.dll";
    string libcrypto_so = "libcrypto.so";
    const string C_DECRYPT_FILE_X = "DecryptFileX";
    const string C_ENCRYPT_FILE_X = "EncryptFileX";
    const string C_ENCRYPT_FILE_INIT = "EncryptFileInit";
    const string C_ENCRYPT_FILE_UPDATE = "EncryptFileUpdate";
    const string C_ENCRYPT_FILE_FINAL = "EncryptFileFinal";
    const string C_FREE_DECRYPTED_MEMORY = "FreeDecryptedMemory";
    const string C_get_shared_secret = "get_shared_secret";

    private const int RTLD_LOCAL = 0x000000;
    private const int RTLD_LAZY = 0x00001; //Only resolve symbols as needed
    private const int RTLD_NOW = 0x00002; // for linux dlopen's flags 
    private const int RTLD_GLOBAL = 0x00100; //Make symbols available to libraries loaded later

    delegate IntPtr DecryptFileX(IntPtr private_key, IntPtr shared_secret, IntPtr filename, int* decrypted_size);
    delegate void FreeDecryptedMemory();
    delegate int EncryptFileX(IntPtr data, UInt32 datasize, IntPtr private_key, IntPtr shared_secret, IntPtr filename);
    delegate int EncryptFileInit(IntPtr private_key, IntPtr shared_secret, IntPtr filename);
    delegate int EncryptFileUpdate(IntPtr data, UInt32 datasize);
    delegate int EncryptFileFinal();
    delegate IntPtr get_shared_secret(IntPtr keyfile, IntPtr shared_secret);
    
    DecryptFileX DecryptFileXHandler;
    FreeDecryptedMemory FreeDecryptedMemoryHandler;
    EncryptFileX EncryptFileXHandler;
    EncryptFileInit EncryptFileInitHandler;
    EncryptFileUpdate EncryptFileUpdateHandler;
    EncryptFileFinal EncryptFileFinalHandler;
    get_shared_secret GetSharedSecretHandler;
    
    internal bool UnloadDllWrapper() {
      if (dll_pointer != null && dll_pointer != IntPtr.Zero) {
        if (isUnix)
          return NativeMethods.dlclose(dll_pointer);
        else
          return NativeMethods.FreeLibrary(dll_pointer);
      
      } else
        return true;
    }

    void CreateDynamicDllWrapper() {
      Func<string, string> fixOSPath = (string path) => isUnix ? path.Replace("\\", "/") : path;

      // System.Console.WriteLine(pid);  
      if ((!isUnix && !File.Exists(fixOSPath(unmanagedDll))) | (!isUnix && !File.Exists(fixOSPath(libeay32_dll))) | (isUnix && !File.Exists(unmanagedDll_so))) {
        throw new Exception(unmanagedDll + " or " + unmanagedDll_so + " or " + libeay32_dll + " cannot be found.");
      }

      if (!isUnix)
        dll_pointer = NativeMethods.LoadLibrary(unmanagedDll);
      else {
        NativeMethods.dlopen(libcrypto_so, RTLD_NOW | RTLD_GLOBAL); 
        dll_pointer = NativeMethods.dlopen(unmanagedDll_so, RTLD_NOW | RTLD_LOCAL);
      }
      if (dll_pointer == IntPtr.Zero) {
        if (isUnix) {
          IntPtr errPtr = NativeMethods.dlerror();
          string errMsg = Marshal.PtrToStringAnsi(errPtr);
          throw new Exception(errMsg);
        } else {
          throw new Win32Exception(Marshal.GetLastWin32Error());
        }
      }

      IntPtr pDecryptFileX = IntPtr.Zero;
      IntPtr pEncryptFileX = IntPtr.Zero;
      IntPtr pFreeDecryptedMemory = IntPtr.Zero;
      IntPtr pEncryptFileInit = IntPtr.Zero;
      IntPtr pEncryptFileUpdate = IntPtr.Zero;
      IntPtr pEncryptFileFinal = IntPtr.Zero;
      IntPtr pGetSharedSecret = IntPtr.Zero;
      
      if (!isUnix) {
        pDecryptFileX = NativeMethods.GetProcAddress(dll_pointer, C_DECRYPT_FILE_X);
        pEncryptFileX = NativeMethods.GetProcAddress(dll_pointer, C_ENCRYPT_FILE_X);
        pFreeDecryptedMemory = NativeMethods.GetProcAddress(dll_pointer, C_FREE_DECRYPTED_MEMORY);
        pEncryptFileInit = NativeMethods.GetProcAddress(dll_pointer, C_ENCRYPT_FILE_INIT);
        pEncryptFileUpdate = NativeMethods.GetProcAddress(dll_pointer, C_ENCRYPT_FILE_UPDATE);
        pEncryptFileFinal = NativeMethods.GetProcAddress(dll_pointer, C_ENCRYPT_FILE_FINAL);
        pGetSharedSecret = NativeMethods.GetProcAddress(dll_pointer, C_get_shared_secret);
      } else {
        pDecryptFileX = NativeMethods.dlsym(dll_pointer, C_DECRYPT_FILE_X);
        pEncryptFileX = NativeMethods.dlsym(dll_pointer, C_ENCRYPT_FILE_X);
        pFreeDecryptedMemory = NativeMethods.dlsym(dll_pointer, C_FREE_DECRYPTED_MEMORY);
        pEncryptFileInit = NativeMethods.dlsym(dll_pointer, C_ENCRYPT_FILE_INIT);
        pEncryptFileUpdate = NativeMethods.dlsym(dll_pointer,  C_ENCRYPT_FILE_UPDATE);
        pEncryptFileFinal = NativeMethods.dlsym(dll_pointer, C_ENCRYPT_FILE_FINAL);
        pGetSharedSecret = NativeMethods.dlsym(dll_pointer, C_get_shared_secret);
      }
      
      DecryptFileXHandler = (DecryptFileX)Marshal.GetDelegateForFunctionPointer(pDecryptFileX, typeof(DecryptFileX));
      EncryptFileXHandler = (EncryptFileX)Marshal.GetDelegateForFunctionPointer(pEncryptFileX, typeof(EncryptFileX));
      FreeDecryptedMemoryHandler = (FreeDecryptedMemory)Marshal.GetDelegateForFunctionPointer(pFreeDecryptedMemory, typeof(FreeDecryptedMemory));
      EncryptFileInitHandler = (EncryptFileInit)Marshal.GetDelegateForFunctionPointer(pEncryptFileInit, typeof(EncryptFileInit));
      EncryptFileUpdateHandler = (EncryptFileUpdate)Marshal.GetDelegateForFunctionPointer(pEncryptFileUpdate, typeof(EncryptFileUpdate));
      EncryptFileFinalHandler = (EncryptFileFinal)Marshal.GetDelegateForFunctionPointer(pEncryptFileFinal, typeof(EncryptFileFinal));
      GetSharedSecretHandler = (get_shared_secret)Marshal.GetDelegateForFunctionPointer(pGetSharedSecret, typeof(get_shared_secret));

    }

    public int DoDecryptFileX(string filename, ref IntPtr p_data) {
      IntPtr p_filename = IntPtr.Zero;
      IntPtr p_privatekey = IntPtr.Zero;
      IntPtr p_sharedsecret = IntPtr.Zero;

      int decrypted_size = 0;

      try {
        p_filename = Marshal.StringToHGlobalAnsi(filename);
        p_sharedsecret = Marshal.StringToHGlobalAnsi(sharedSecret);
        p_privatekey = Marshal.StringToHGlobalAnsi(privateKey);

        decrypt_file_x_ptr = DecryptFileXHandler(p_privatekey, p_sharedsecret, p_filename, &decrypted_size);

        if (decrypted_size > 0) {
          p_data = Marshal.AllocHGlobal(decrypted_size);
          NativeMethods.MemCopy(p_data, decrypt_file_x_ptr, (uint)decrypted_size);
        }
        FreeDecryptedMemoryHandler();
      } catch (Exception e) {
        GetLastError = e.Message;
      } finally {
        if (p_filename != IntPtr.Zero) Marshal.FreeHGlobal(p_filename);
        if (p_privatekey != IntPtr.Zero) Marshal.FreeHGlobal(p_privatekey);
        if (p_sharedsecret != IntPtr.Zero) Marshal.FreeHGlobal(p_sharedsecret);
      }
      return decrypted_size;
    }


    public int DoEncryptFileInit(string filename) {
      IntPtr p_filename = IntPtr.Zero;
      IntPtr p_privatekey = IntPtr.Zero;
      IntPtr p_sharedsecret = IntPtr.Zero;
      int rc = 0;

      try {
        p_filename = Marshal.StringToHGlobalAnsi(filename);
        p_privatekey = Marshal.StringToHGlobalAnsi(privateKey);
        p_sharedsecret = Marshal.StringToHGlobalAnsi(sharedSecret);

        rc = EncryptFileInitHandler(p_privatekey, p_sharedsecret, p_filename);
      } catch (Exception ex) {
        GetLastError = ex.Message;
      } finally {
        if (p_filename != IntPtr.Zero) Marshal.FreeHGlobal(p_filename);
        if (p_privatekey != IntPtr.Zero) Marshal.FreeHGlobal(p_privatekey);
        if (p_sharedsecret != IntPtr.Zero) Marshal.FreeHGlobal(p_sharedsecret);
      }

      return rc;
    }

    public int DoEncryptFileUpdate(IntPtr p_data, int stream_len) {
      int rc = 0;
      try {
        rc = EncryptFileUpdateHandler(p_data, (uint)stream_len);
      } catch (Exception ex) {
        GetLastError = ex.Message;
      }
      return rc;
    }

    public int DoEncryptFileFinal() {
      int rc = 0;

      try {
        rc = EncryptFileFinalHandler();
      } catch (Exception ex) {
        GetLastError = ex.Message;
      }
      return rc;
    }

    public int DoEncryptFileX(IntPtr p_data, long stream_len, string filename) {
      IntPtr p_filename = IntPtr.Zero;
      IntPtr p_privatekey = IntPtr.Zero;
      IntPtr p_sharedsecret = IntPtr.Zero;
      int idatawritten = 0;

      try {
        p_filename = Marshal.StringToHGlobalAnsi(filename);
        p_privatekey = Marshal.StringToHGlobalAnsi(privateKey);
        p_sharedsecret = Marshal.StringToHGlobalAnsi(sharedSecret);

        idatawritten = EncryptFileXHandler(p_data, (uint)stream_len, p_privatekey, p_sharedsecret, p_filename);
      } catch (Exception ex) {
        GetLastError = ex.Message;
      } finally {
        if (p_filename != IntPtr.Zero) Marshal.FreeHGlobal(p_filename);
        if (p_privatekey != IntPtr.Zero) Marshal.FreeHGlobal(p_privatekey);
        if (p_sharedsecret != IntPtr.Zero) Marshal.FreeHGlobal(p_sharedsecret);
      }

      return idatawritten;
    }

    public string DoGetSharedSecret() {
      IntPtr p_privatekey = IntPtr.Zero;
      IntPtr p_sharedsecret = IntPtr.Zero;
      string retval = "";
      try {
        if (isUnix) {
          privateKey = privateKey.Replace("\\", "/");
          sharedSecret = sharedSecret.Replace("\\", "/");
        }
        p_privatekey = Marshal.StringToHGlobalAnsi(privateKey);
        p_sharedsecret = Marshal.StringToHGlobalAnsi(sharedSecret);
        
        IntPtr shared_secret = GetSharedSecretHandler(p_privatekey, p_sharedsecret);
        if (shared_secret == IntPtr.Zero)
          throw new Win32Exception(Marshal.GetLastWin32Error());
        retval = Marshal.PtrToStringAnsi(shared_secret);
      } catch (Win32Exception w) {
        throw w;
      } catch (Exception e) {
        throw e; // GetLastError = e.Message; 
      } finally {

        if (p_privatekey != IntPtr.Zero) Marshal.FreeHGlobal(p_privatekey);
        if (p_sharedsecret != IntPtr.Zero) Marshal.FreeHGlobal(p_sharedsecret);
      }
      return retval;
    }
  }
}
