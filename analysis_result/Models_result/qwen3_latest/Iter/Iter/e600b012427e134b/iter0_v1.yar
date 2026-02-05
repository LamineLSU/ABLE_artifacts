rule ExitProcess_Call
{
    meta:
        description = "Identifies a call to ExitProcess with surrounding instructions"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }
    condition:
        $a
}