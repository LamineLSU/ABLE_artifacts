rule ExitProcess_Call
{
    meta:
        description = "Detects the direct call to ExitProcess with preceding push"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
    strings:
        $a = { 6A 00 } // push 0x00
        $b = { E8 ?? ?? ?? ?? } // call ExitProcess (offset replaced)
    condition:
        $a and $b
}