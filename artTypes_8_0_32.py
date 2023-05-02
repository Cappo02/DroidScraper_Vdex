# -*- coding: utf-8 -*-
"""
    @credit: Aisha Ali-Gombe (aaligombe@towson.edu)
    @contributors: Alexandre Blanchon, Arthur Belleville, Corentin Jeudy

    Brief: artTypes offsets - Android 8.0 (32 bits)
"""

types = {
	'Monitor': [0x60, {
		'monitor_lock_': [0],
		'monitor_contenders_': [40],
		'num_waiters_': [56],
		'owner_': [60],
		'lock_count_': [64],
		'obj_': [68],
		'wait_set_': [72],
		'hash_code_': [76],
		'locking_method_': [80],
		'locking_dex_pc_': [84],
		'monitor_id_': [88],
	}],

	# Manually changed
	'Thread': [0x528, { 
		'tls32_': [0],
		'tls64_': [64],
		'tlsPtr_': [128],
		'wait_mutex_': [1280],
		'wait_cond_': [1284],
		'wait_monitor_': [1288],
		'interrupted_': [1292],
		'debug_disallow_read_barrier_': [1293],
		'poison_object_cookie_': [1296],
		'checkpoint_overflow_': [1300],
		'custom_tls_': [1312],
		'can_call_into_java_': [1316],
	}],

	'ArtMethod': [0x20, {
		'declaring_class_': [0],
		'access_flags_': [4],
		'dex_code_item_offset_': [8],
		'dex_method_index_': [12],
		'method_index_': [16],
		'hotness_count_': [18],
		'ptr_sized_fields_': [20],
	}],

	'ArtField': [0x10, {
		'declaring_class_': [0],
		'access_flags_': [4],
		'field_dex_idx_': [8],
		'offset_': [12],
	}],

	'IRTSegmentState': [0x4, {
		'top_index': [0],
	}],

	'IndirectReferenceTable': [0x20, {
		'segment_state_': [0],
		'table_mem_map_': [4],
		'table_': [8],
		'kind_': [12],
		'max_entries_': [16],
		'current_num_holes_': [20],
		'last_known_previous_state_': [24],
		'resizable_': [28],
	}],

	'IrtEntry': [0x10, {
		'serial_': [0],
		'references_': [4],
	}],

	'GcRoot<art::mirror::Object>': [0x4, {
		'root_': [0],
	}],

	'Runtime': [0x348, {
		'callee_save_methods_': [0],
		'pre_allocated_OutOfMemoryError_': [32],
		'pre_allocated_NoClassDefFoundError_': [36],
		'resolution_method_': [40],
		'imt_conflict_method_': [44],
		'imt_unimplemented_method_': [48],
		'sentinel_': [52],
		'instruction_set_': [56],
		'callee_save_method_frame_infos_': [60],
		'compiler_callbacks_': [108],
		'is_zygote_': [112],
		'must_relocate_': [113],
		'is_concurrent_gc_enabled_': [114],
		'is_explicit_gc_disabled_': [115],
		'dex2oat_enabled_': [116],
		'image_dex2oat_enabled_': [117],
		'compiler_executable_': [120],
		'patchoat_executable_': [132],
		'compiler_options_': [144],
		'image_compiler_options_': [156],
		'image_location_': [168],
		'boot_class_path_string_': [180],
		'class_path_string_': [192],
		'properties_': [204],
		'agents_': [216],
		'plugins_': [228],
		'default_stack_size_': [240],
		'heap_': [244],
		'jit_arena_pool_': [248],
		'arena_pool_': [252],
		'low_4gb_arena_pool_': [256],
		'linear_alloc_': [260],
		'max_spins_before_thin_lock_inflation_': [264],
		'monitor_list_': [268],
		'monitor_pool_': [272],
		'thread_list_': [276],
		'intern_table_': [280],
		'class_linker_': [284],
		'signal_catcher_': [288],
		'use_tombstoned_traces_': [292],
		'stack_trace_file_': [296],
		'java_vm_': [308],
		'jit_': [312],
		'jit_options_': [316],
		'fault_message_lock_': [320],
		'fault_message_': [360],
		'threads_being_born_': [372],
		'shutdown_cond_': [376],
		'shutting_down_': [380],
		'shutting_down_started_': [381],
		'started_': [382],
		'finished_starting_': [383],
		'vfprintf_': [384],
		'exit_': [388],
		'abort_': [392],
		'stats_enabled_': [396],
		'stats_': [400],
		'is_running_on_memory_tool_': [456],
		'trace_config_': [460],
		'instrumentation_': [464],
		'main_thread_group_': [680],
		'system_thread_group_': [684],
		'system_class_loader_': [688],
		'dump_gc_performance_on_shutdown_': [692],
		'preinitialization_transaction_': [696],
		'verify_': [700],
		'allow_dex_file_fallback_': [701],
		'cpu_abilist_': [704],
		'target_sdk_version_': [716],
		'implicit_null_checks_': [720],
		'implicit_so_checks_': [721],
		'implicit_suspend_checks_': [722],
		'no_sig_chain_': [723],
		'force_native_bridge_': [724],
		'is_native_bridge_loaded_': [725],
		'is_native_debuggable_': [726],
		'is_java_debuggable_': [727],
		'zygote_max_failed_boots_': [728],
		'experimental_flags_': [732],
		'fingerprint_': [736],
		'oat_file_manager_': [748],
		'is_low_memory_mode_': [752],
		'safe_mode_': [753],
		'dump_native_stack_on_sig_quit_': [754],
		'pruned_dalvik_cache_': [755],
		'process_state_': [756],
		'zygote_no_threads_': [760],
		'env_snapshot_': [764],
		'system_weak_holders_': [780],
		'cha_': [792],
		'callbacks_': [796],
		'deoptimization_counts_': [800],
		'protected_fault_page_': [832],
	}],

	'ThreadList': [0x208c, {
		'allocated_ids_': [0],
		'list_': [8192],
		'suspend_all_count_': [8204],
		'debug_suspend_all_count_': [8208],
		'unregistering_count_': [8212],
		'suspend_all_historam_': [8216],
		'long_suspend_': [8316],
		'shut_down_': [8317],
		'thread_suspend_timeout_ns_': [8320],
		'empty_checkpoint_barrier_': [8328],
	}],

	'JavaVMExt': [0x88, {
		'runtime_': [4],
		'check_jni_abort_hook_': [8],
		'check_jni_abort_hook_data_': [12],
		'check_jni_': [16],
		'force_copy_': [17],
		'tracing_enabled_': [18],
		'trace_': [20],
		'globals_': [32],
		'libraries_': [64],
		'unchecked_functions_': [68],
		'weak_globals_': [72],
		'allow_accessing_weak_globals_': [104],
		'weak_globals_add_condition_': [108],
		'env_hooks_': [124],
	}],

	'DexFile': [0x50, {
		'_vptr$DexFile': [0],
		'begin_': [4],
		'size_': [8],
		'location_': [12],
		'location_checksum_': [24],
		'mem_map_': [28],
		'header_': [32],
		'string_ids_': [36],
		'type_ids_': [40],
		'field_ids_': [44],
		'method_ids_': [48],
		'proto_ids_': [52],
		'class_defs_': [56],
		'method_handles_': [60],
		'num_method_handles_': [64],
		'call_site_ids_': [68],
		'num_call_site_ids_': [72],
		'oat_dex_file_': [76],
	}],

	'OatFile': [0x88, {
		'_vptr$OatFile': [0],
		'location_': [4],
		'vdex_': [16],
		'begin_': [20],
		'end_': [24],
		'bss_begin_': [28],
		'bss_end_': [32],
		'bss_roots_': [36],
		'is_executable_': [40],
		'oat_dex_files_storage_': [44],
		'oat_dex_files_': [56],
		'secondary_lookup_lock_': [72],
		'secondary_oat_dex_files_': [112],
		'string_cache_': [124],
	}],

	'tls_32bit_sized_values': [0x44, {
		'state_and_flags': [0],
		'suspend_count': [4],
		'debug_suspend_count': [8],
		'thin_lock_thread_id': [12],
		'tid': [16],
		'daemon': [20],
		'throwing_OutOfMemoryError': [24],
		'no_thread_suspension': [28],
		'thread_exit_check_count': [32],
		'handling_signal_': [36],
		'is_transitioning_to_runnable': [40],
		'ready_for_debug_invoke': [44],
		'debug_method_entry_': [48],
		'is_gc_marking': [52],
		'interrupted': [56],
		'weak_ref_access_enabled': [60],
		'disable_thread_flip_count': [64],
		'as_struct': [0],
		'as_atomic_int': [0],
		'as_int': [0],
	}],

	'tls_64bit_sized_values': [0x40, {
		'trace_clock_base': [0],
		'stats': [8],
	}],

	'tls_ptr_sized_values': [0x480, {
		'card_table': [0],
		'exception': [4],
		'stack_end': [8],
		'managed_stack': [12],
		'suspend_trigger': [24],
		'jni_env': [28],
		'tmp_jni_env': [32],
		'self': [36],
		'opeer': [40],
		'jpeer': [44],
		'stack_begin': [48],
		'stack_size': [52],
		'deps_or_stack_trace_sample': [56],
		'wait_next': [60],
		'monitor_enter_object': [64],
		'top_handle_scope': [68],
		'class_loader_override': [72],
		'long_jump_context': [76],
		'instrumentation_stack': [80],
		'debug_invoke_req': [84],
		'single_step_control': [88],
		'stacked_shadow_frame_record': [92],
		'deoptimization_context_stack': [96],
		'frame_id_to_shadow_frame': [100],
		'name': [104],
		'pthread_self': [108],
		'last_no_thread_suspension_cause': [112],
		'checkpoint_function': [116],
		'active_suspend_barriers': [120],
		'thread_local_start': [132],
		'thread_local_pos': [136],
		'thread_local_end': [140],
		'thread_local_limit': [144],
		'thread_local_objects': [148],
		'jni_entrypoints': [152],
		'quick_entrypoints': [156],
		'mterp_current_ibase': [800],
		'mterp_default_ibase': [804],
		'mterp_alt_ibase': [808],
		'rosalloc_runs': [812],
		'thread_local_alloc_stack_top': [876],
		'thread_local_alloc_stack_end': [880],
		'held_mutexes': [884],
		'flip_function': [1140],
		'method_verifier': [1144],
		'thread_local_mark_stack': [1148],
	}],

	'CompressedReference<art::mirror::Object>': [0x4, {
	}],

	'ObjectReference<false, art::mirror::Object>': [0x4, {
		'reference_': [0],
	}],

	'Object': [0x8, {
		'klass_': [0],
		'monitor_': [4],
	}],

	'Class': [0x78, {
		'class_loader_': [8],
		'component_type_': [12],
		'dex_cache_': [16],
		'ext_data_': [20],
		'iftable_': [24],
		'name_': [28],
		'super_class_': [32],
		'vtable_': [36],
		'ifields_': [40],
		'methods_': [48],
		'sfields_': [56],
		'access_flags_': [64],
		'class_flags_': [68],
		'class_size_': [72],
		'clinit_thread_id_': [76],
		'dex_class_def_idx_': [80],
		'dex_type_idx_': [84],
		'num_reference_instance_fields_': [88],
		'num_reference_static_fields_': [92],
		'object_size_': [96],
		'object_size_alloc_fast_path_': [100],
		'primitive_type_': [104],
		'reference_instance_offsets_': [108],
		'status_': [112],
		'copied_methods_offset_': [116],
		'virtual_methods_offset_': [118],
	}],

	'DexCache': [0x5c, {
		'location_': [8],
		'num_resolved_call_sites_': [12],
		'dex_file_': [16],
		'resolved_call_sites_': [24],
		'resolved_fields_': [32],
		'resolved_method_types_': [40],
		'resolved_methods_': [48],
		'resolved_types_': [56],
		'strings_': [64],
		'num_resolved_fields_': [72],
		'num_resolved_method_types_': [76],
		'num_resolved_methods_': [80],
		'num_resolved_types_': [84],
		'num_strings_': [88],
	}],

	'String': [0x10, {
		'count_': [8],
		'hash_code_': [12],
		'': [16],
	}],

	'PtrSizedFields': [0xc, {
		'dex_cache_resolved_methods_': [0],
		'data_': [4],
		'entry_point_from_quick_compiled_code_': [8],
	}],

	'ProtoId': [0xc, {
		'shorty_idx_': [0],
		'return_type_idx_': [4],
		'pad_': [6],
		'parameters_off_': [8],
	}],

	'ClassDef': [0x20, {
		'class_idx_': [0],
		'pad1_': [2],
		'access_flags_': [4],
		'superclass_idx_': [8],
		'pad2_': [10],
		'interfaces_off_': [12],
		'source_file_idx_': [16],
		'annotations_off_': [20],
		'class_data_off_': [24],
		'static_values_off_': [28],
	}],

	'FieldId': [0x8, {
		'class_idx_': [0],
		'type_idx_': [2],
		'name_idx_': [4],
	}],

	'TypeId': [0x4, {
		'descriptor_idx_': [0],
	}],

	'StringId': [0x4, {
		'string_data_off_': [0],
	}],

	'MethodId': [0x8, {
		'class_idx_': [0],
		'proto_idx_': [2],
		'name_idx_': [4],
	}],

	'Field': [0x20, {
		'padding_': [10],
		'declaring_class_': [12],
		'type_': [16],
		'access_flags_': [20],
		'dex_field_index_': [24],
		'offset_': [28],
	}],

	'RegionSpace': [0xa8, {
		'region_lock_': [56],
		'time_': [96],
		'num_regions_': [100],
		'num_non_free_regions_': [104],
		'regions_': [108],
		'non_free_region_index_limit_': [112],
		'current_region_': [116],
		'evac_region_': [120],
		'full_region_': [124],
		'mark_bitmap_': [164],
	}],

	'ContinuousMemMapAllocSpace': [0x34, {
		'live_bitmap_': [40],
		'mark_bitmap_': [44],
		'temp_bitmap_': [48],
	}],

	'MemMapSpace': [0x24, {
		'mem_map_': [32],
	}],

	'ContinuousSpace': [0x20, {
		'begin_': [20],
		'end_': [24],
		'limit_': [28],
	}],

	'AllocSpace': [0x4, {
		'_vptr$AllocSpace': [0],
	}],

	'ImageSpace': [0x3c, {
		'live_bitmap_': [36],
		'oat_file_': [40],
		'oat_file_non_owned_': [44],
		'image_location_': [48],
	}],

	'MallocSpace': [0x70, {
		'recent_freed_objects_': [52],
		'recent_free_pos_': [52],
		'lock_': [56],
		'growth_limit_': [96],
		'can_move_objects_': [100],
		'starting_size_': [104],
		'initial_size_': [108],
	}],

	'Region': [0x28, {
		'idx_': [0],
		'begin_': [4],
		'top_': [8],
		'end_': [12],
		'state_': [16],
		'type_': [17],
		'objects_allocated_': [20],
		'alloc_time_': [24],
		'live_bytes_': [28],
		'is_newly_allocated_': [32],
		'is_a_tlab_': [33],
		'thread_': [36],
	}],

	'Heap': [0x388, {
		'continuous_spaces_': [0],
		'discontinuous_spaces_': [12],
		'alloc_spaces_': [24],
		'non_moving_space_': [36],
		'rosalloc_space_': [40],
		'dlmalloc_space_': [44],
		'main_space_': [48],
		'large_object_space_': [52],
		'card_table_': [56],
		'rb_table_': [60],
		'mod_union_tables_': [64],
		'remembered_sets_': [76],
		'collector_type_': [88],
		'foreground_collector_type_': [92],
		'background_collector_type_': [96],
		'desired_collector_type_': [100],
		'pending_task_lock_': [104],
		'parallel_gc_threads_': [108],
		'conc_gc_threads_': [112],
		'low_memory_mode_': [116],
		'long_pause_log_threshold_': [120],
		'long_gc_log_threshold_': [124],
		'ignore_max_footprint_': [128],
		'zygote_creation_lock_': [136],
		'zygote_space_': [176],
		'large_object_threshold_': [180],
		'gc_complete_lock_': [184],
		'gc_complete_cond_': [188],
		'thread_flip_lock_': [192],
		'thread_flip_cond_': [196],
		'disable_thread_flip_count_': [200],
		'thread_flip_running_': [204],
		'reference_processor_': [208],
		'task_processor_': [212],
		'collector_type_running_': [216],
		'last_gc_cause_': [220],
		'thread_running_gc_': [224],
		'last_gc_type_': [228],
		'next_gc_type_': [232],
		'capacity_': [236],
		'growth_limit_': [240],
		'max_allowed_footprint_': [244],
		'concurrent_start_bytes_': [248],
		'total_bytes_freed_ever_': [252],
		'total_objects_freed_ever_': [260],
		'num_bytes_allocated_': [268],
		'new_native_bytes_allocated_': [272],
		'old_native_bytes_allocated_': [276],
		'native_blocking_gc_lock_': [280],
		'native_blocking_gc_cond_': [284],
		'native_blocking_gc_is_assigned_': [288],
		'native_blocking_gc_in_progress_': [289],
		'native_blocking_gcs_finished_': [292],
		'num_bytes_freed_revoke_': [296],
		'current_gc_iteration_': [300],
		'verify_missing_card_marks_': [388],
		'verify_system_weaks_': [389],
		'verify_pre_gc_heap_': [390],
		'verify_pre_sweeping_heap_': [391],
		'verify_post_gc_heap_': [392],
		'verify_mod_union_table_': [393],
		'verify_pre_gc_rosalloc_': [394],
		'verify_pre_sweeping_rosalloc_': [395],
		'verify_post_gc_rosalloc_': [396],
		'gc_stress_mode_': [397],
		'thread_pool_': [400],
		'allocation_rate_': [404],
		'live_bitmap_': [412],
		'mark_bitmap_': [416],
		'mark_stack_': [420],
		'max_allocation_stack_size_': [424],
		'allocation_stack_': [428],
		'live_stack_': [432],
		'current_allocator_': [436],
		'current_non_moving_allocator_': [440],
		'gc_plan_': [444],
		'bump_pointer_space_': [456],
		'temp_space_': [460],
		'region_space_': [460], # 460 to make DroidScraper work. (In theory it should be 464). 
		'min_free_': [468],
		'max_free_': [472],
		'target_utilization_': [476],
		'foreground_heap_growth_multiplier_': [484],
		'total_wait_time_': [492],
		'verify_object_mode_': [500],
		'disable_moving_gc_count_': [504],
		'garbage_collectors_': [508],
		'semi_space_collector_': [520],
		'mark_compact_collector_': [524],
		'concurrent_copying_collector_': [528],
		'is_running_on_memory_tool_': [532],
		'use_tlab_': [533],
		'main_space_backup_': [536],
		'min_interval_homogeneous_space_compaction_by_oom_': [540],
		'last_time_homogeneous_space_compaction_by_oom_': [548],
		'count_delayed_oom_': [556],
		'count_requested_homogeneous_space_compaction_': [560],
		'count_ignored_homogeneous_space_compaction_': [564],
		'count_performed_homogeneous_space_compaction_': [568],
		'concurrent_gc_pending_': [572],
		'pending_collector_transition_': [576],
		'pending_heap_trim_': [580],
		'use_homogeneous_space_compaction_for_oom_': [584],
		'running_collection_is_blocking_': [585],
		'blocking_gc_count_': [588],
		'blocking_gc_time_': [596],
		'last_update_time_gc_count_rate_histograms_': [604],
		'gc_count_last_window_': [612],
		'blocking_gc_count_last_window_': [620],
		'gc_count_rate_histogram_': [628],
		'blocking_gc_count_rate_histogram_': [728],
		'alloc_tracking_enabled_': [828],
		'allocation_records_': [832],
		'backtrace_lock_': [836],
		'seen_backtrace_count_': [840],
		'unique_backtrace_count_': [848],
		'seen_backtraces_': [856],
		'gc_disabled_for_shutdown_': [876],
		'boot_image_spaces_': [880],
		'alloc_listener_': [892],
		'gc_pause_listener_': [896],
		'verification_': [900],
	}],

	'SpaceBitmap':[0x1c,{
		'mem_map_' : [0],
		'bitmap_begin_' :[4],
		'bitmap_size_':[8],
		'heap_begin_': [12],
		'name_': [16],
	}],

	'VdexFile': [0x4, {
		'mmap_': [0],
	}],

	'MemMap': [0x28, {
		'name_': [0],
		'begin_': [12],
		'size_': [16],
		'base_begin_': [20],
		'base_size_': [24],
		'prot_': [28],
		'reuse_': [32],
		'redzone_size_': [36],
	}],

	'VdexHeader': [0x18, {
		'magic_': [0],
		'version_': [4],
		'number_of_dex_files': [8],
		'dex_size_': [12],
		'verifier_deps_size_': [16],
		'quickening_info_size': [20],
	}],

}