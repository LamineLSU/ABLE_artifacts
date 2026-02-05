rule Bypass_Sample_1
{
    meta:
        description = "Bypass: Disrupt EBP push and MOV"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 55 56 8B EC E8 ?? ?? ?? ?? 85 C0 }  // push ebp; push esi; mov ebp, esp; call; test eax

    condition:
        any of them
}