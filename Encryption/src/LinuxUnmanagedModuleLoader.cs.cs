/*
Copyright (c) 2012-2015 Stugo Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Stugo.Interop.Linux
{
    public class LinuxUnmanagedModuleLoader : UnmanagedModuleLoaderBase
    {
        const int RTLD_NOW = 2; // for dlopen's flags 

        [DllImport("libdl.so")]
        protected static extern IntPtr dlopen(string filename, int flags);

        [DllImport("libdl.so")]
        protected static extern IntPtr dlsym(IntPtr handle, string symbol);


        /// <summary>
        /// Gets the handle for the unmanaged library.
        /// </summary>
        protected IntPtr ModuleHandle { get; private set; }


        /// <summary>
        /// Creates a new instance.
        /// </summary>
        /// <param name="modulePath">The path to the module.</param>
        public LinuxUnmanagedModuleLoader(string modulePath)
            : base(modulePath)
        {
            this.ModuleHandle = dlopen(modulePath, RTLD_NOW);

            // give a meaningful error if the library cannot be loaded.
            if (this.ModuleHandle == IntPtr.Zero)
            {
                throw new ArgumentException(
                    string.Format(
                        "Unable to load unmanaged module \"{0}\"",
                        modulePath));
            }
        }


        /// <summary>
        /// When overriden in a derived class, gets a pointer to an unmanaged method.
        /// </summary>
        /// <param name="methodName">The name of the method to get a pointer for.</param>
        /// <returns>The method pointer.</returns>
        protected override IntPtr getUnmanagedMethodPointer(string methodName)
        {
            IntPtr ptr = dlsym(this.ModuleHandle, methodName);

            if (ptr == IntPtr.Zero)
                throw new MissingMethodException(
                    string.Format(
                        "The unmanaged method \"{0}\" does not exist",
                        methodName));

            return ptr;
        }
    }
}
