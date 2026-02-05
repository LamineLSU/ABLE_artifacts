rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + JZ (early sandbox check)
        $pattern1 = { 53 FF 15 ?? ?? ?? ?? }     // Push EBX + Call ExitProcess (evasion termination)
        $pattern2 = { 8B CE E8 ?? ?? ?? ?? }     // Move ECX + Call (functionality check before exit)

    condition: all of them
}