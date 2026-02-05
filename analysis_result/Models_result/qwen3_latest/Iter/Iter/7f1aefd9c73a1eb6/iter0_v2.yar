rule ExitProcessCall
{
    meta:
        description = "Attempt to call ExitProcess to terminate execution"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 53 FF 15 ?? ?? ?? ?? } // push ebx followed by call to ExitProcess
    condition:
        all of them
}