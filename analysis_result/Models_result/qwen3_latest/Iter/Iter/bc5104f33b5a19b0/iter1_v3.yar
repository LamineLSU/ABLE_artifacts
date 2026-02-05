rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 4B FF 15 ?? ?? ?? ?? }  // Test, je, and call instruction (10 bytes)
        $pattern1 = { FF 15 ?? ?? ?? ?? }              // Call to AllocConsole (6 bytes)
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? }        // Test and jz instruction (8 bytes)

    condition:
        all of them
}