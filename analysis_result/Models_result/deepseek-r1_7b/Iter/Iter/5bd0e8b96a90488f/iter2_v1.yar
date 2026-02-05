rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass rule targeting multiple points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } <!-- TEST EAX + JZ + mov -->
        $pattern1 = { E8 ?? ?? ?? ?? 75 ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? } <!-- call with operands followed by conditional jump -->
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } <!-- another distinct instruction sequence -->

    condition:
        any of them
}