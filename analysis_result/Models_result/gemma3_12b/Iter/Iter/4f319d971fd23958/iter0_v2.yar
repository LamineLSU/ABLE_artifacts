rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 88 18 0A 00 00 56 6A 36 5A }
        // 8B 88 18 0A 00 00: mov ecx, dword ptr [eax+0A18h]
        // 56: push esi
        // 6A 36: push 36h
        // 5A: pop ya

    condition:
        any of them
}