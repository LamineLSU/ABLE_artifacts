rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific lea instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A A1 AC5B3502 E8 ?? 8D854CF2FFFF lea eax, dword ptr [ebp-00000DB4h] }
        $pattern1 = { 5A 8B CE E8 ?? 8D854CF2FFFF lea eax, dword ptr [ebp-00000DB8h] }
        $pattern2 = { 5A A1 AC5B3502 E8 ?? 8D854CF2FFFF lea eax, dword ptr [ebp-00000DBCh] }

    condition:
        any of them
}