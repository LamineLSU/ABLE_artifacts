rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  //Bypass test eax, eax
        $pattern1 = { FF 15 88 A0 17 01 ?? ?? ?? ?? } //Bypass call dword ptr [0117A088h]
        $pattern2 = { FF 15 2C A1 17 01 ?? ?? ?? ?? } //Bypass call dword ptr [0117A12Ch]

    condition:
        any of them
}