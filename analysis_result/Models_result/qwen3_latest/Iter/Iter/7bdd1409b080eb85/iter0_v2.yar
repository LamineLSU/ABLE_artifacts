rule Pattern0
{
    meta:
        description = "Detects first call to GetModuleHandleA"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 68 1C 27 47 00 FF 15 ?? ?? ?? ?? 85 C0 }
    condition:
        all of them
}