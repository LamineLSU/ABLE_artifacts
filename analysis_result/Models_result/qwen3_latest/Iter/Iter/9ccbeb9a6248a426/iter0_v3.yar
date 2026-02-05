rule ExitProcess_Conditional_Call
{
    meta:
        description = "Detects a conditional call to ExitProcess, including test, jump, and push operations."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2025-04-07"

    strings:
        $a = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Test EAX, JZ, MOV EAX, [EBP-?]
        $b = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }  // CALL, ADD, TEST, JZ
        $c = { 74 07 50 FF 15 ?? ?? ?? ?? }  // JNE, PUSH, CALL to ExitProcess

    condition:
        $a or $b or $c
}