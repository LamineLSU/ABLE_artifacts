rule ExitProcess_Caller1
{
    meta:
        description = "Call to ExitProcess with preceding push ebx"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 53 E8 ?? ?? ?? ?? }  // push ebx followed by call to ExitProcess
    condition:
        $a
}