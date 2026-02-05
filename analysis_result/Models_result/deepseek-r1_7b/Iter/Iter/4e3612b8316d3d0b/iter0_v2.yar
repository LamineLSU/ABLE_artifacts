rule bypass_exit_3 {
    include -start
    include push-ebp mov-esp
    include push dword ptr [ebp+8h]
    continue;
}