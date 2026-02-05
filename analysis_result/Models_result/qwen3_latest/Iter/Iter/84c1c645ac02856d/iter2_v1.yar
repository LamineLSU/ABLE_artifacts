rule EvasionDetection
{
    meta:
        description = "Detects evasion techniques via suspicious function calls and conditional jumps"
        cape_options = "bp0=$call1+0,action0=skip,bp1=$check1+0,action1=skip,bp2=$call2+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-15"

    strings:
        // Pattern 1: Push EAX followed by a call (exit point)
        $call1 = { 50 68 ?? ?? ?? ?? }  // 50 = push eax, 68 = push dword, followed by 4 bytes of call address

        // Pattern 2: Push 0, add byte, push ESI (memory check)
        $check1 = { 6A 00 00 51 8D 56 }  // 6A 00 = push 0, 00 51 8D = add [ecx-73], dl, 56 = push esi

        // Pattern 3: LEA ESI, [eax+0CA0h] followed by a call (memory access check)
        $call2 = { 8D B0 A0 0C 00 00 68 ?? ?? ?? ?? }  // 8D B0 A0 0C 00 00 = lea esi, [eax+0CA0h], 68 = push dword with 4 bytes of call address

    condition:
        all of ($call1, $check1, $call2)
}