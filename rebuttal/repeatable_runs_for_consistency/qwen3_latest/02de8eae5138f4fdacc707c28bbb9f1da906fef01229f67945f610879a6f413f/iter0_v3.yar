rule ExitProcess_Call_1
{
    meta:
        description = "Detects the call to ExitProcess followed by a call to 00401031"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
    condition:
        $a
}