rule Evasion_Control_Flow
{
    meta:
        description = "Detects potential evasion or control flow manipulation via test, jump, and call instructions"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2025-04-15"

    strings:
        $a = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? } // Test, je, push, pop, mov, call
        $b = { 85 C0 0F 84 ?? ?? ?? ?? }                 // Test followed by je
        $c = { E8 ?? ?? ?? ?? }                        // Call instruction with variable offset

    condition:
        all of ($a or $b or $c)
}