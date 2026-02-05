rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? }  // Test EAX and skip based on condition
        $pattern1 = { FF 75 08 5A 8B CE E8 ?? ?? }  // Push value to stack and call subroutine
        $pattern2 = { E8 C8 FF FF BE 5F 0F EF FF ?? ?? }  // Call function with specific arguments

    condition:
        any of them
}