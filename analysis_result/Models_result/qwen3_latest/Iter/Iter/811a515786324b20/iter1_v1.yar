rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D ?? E8 ?? ?? ?? ?? }  // mov + call (data prep)
        $pattern1 = { E8 ?? ?? ?? ?? 89 45 ?? }   // call + mov (result storage)
        $pattern2 = { 33 C0 E8 ?? ?? ?? ?? }      // xor + call (zero-based check)

    condition:
        any of them
}