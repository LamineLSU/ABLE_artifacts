rule ExitPointAnalysis
{
    meta:
        description = "Identifies potential exit points in code based on conditional jumps and function calls."
        cape_options = "bp0=$test_jump+0,action0=skip,bp1=$virtual_protect_call+0,action1=skip,bp2=$short_jump+0,action2=skip,count=0"

    strings:
        // Pattern 1: Test EAX and near jump
        $test_jump = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }

        // Pattern 2: Pushes and call to VirtualProtect
        $virtual_protect_call = { 50 54 6A 04 53 57 57 FF D5 }

        // Pattern 3: Short jump after register manipulation
        $short_jump = { 24 0F C1 E0 10 66 8B 07 83 C7 02 EB E2 }

    condition:
        $test_jump or $virtual_protect_call or $short_jump
}