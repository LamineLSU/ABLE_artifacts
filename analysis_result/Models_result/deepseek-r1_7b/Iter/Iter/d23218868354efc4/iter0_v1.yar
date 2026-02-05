rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using multiple bypass vectors"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 F0 0F 84 8B CE ?? ?? ?? E8 C8 F0 0F 84 75 0A ?? ?? }  // Combined multiple instructions with wildcards

        $pattern1 = { FF C8 2C 53 ?? ?? ?? FF C8 6A 5B ?? ?? FF C8 E8 4F ?? ?? }  // Includes various instruction sequences with wildcards

        $pattern2 = { 05 C1 74 12 ?? ?? 05 C1 75 0A ?? ?? 05 C1 03 99 ?? ?? }  // Different instruction combinations for bypassing
    condition:
        any of them
}