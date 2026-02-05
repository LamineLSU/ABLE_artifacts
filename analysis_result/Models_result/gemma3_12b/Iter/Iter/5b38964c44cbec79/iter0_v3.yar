rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC 53 FF 75 08 } // Bypass Trace //1, //3, #4 - push ebp, mov ebp, esp, push ebp, push ebp
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 } // Bypass Trace //5 - mov eax, fs:[0x30], mov eax, [eax+68], shr eax, 08
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Bypass Trace //5 - push, pop, mov, call, test

    condition:
        any of them
}