#include "utils.tcc"
#include "note.tcc"
#include "commitment.tcc"
#include "merkle.tcc"

/***********************************************************
 * 模块整合，主要包括验证proof时所需要的publicData的输入
 ***********************************************************
 * sha256_two_block_gadget, addition_constraint, 
 * sha256_three_block_gadget, merkle_gadget
 **************************************************************
 * sha256_two(data+padding), 512bits < data.size() < 1024-64-1bits
 * sha256_three(data+padding), 1024bits < data.size() < 1536-64-1bits
 * ************************************************************
 * publicData:  pk_B', cmtB_old, cmtB, sn_B_old, rt_cmt
 * privateData: cmtS, value_s, sn_s, r_s, sn_A_old
 *              value_old, r_B_old
 *              value_new, sn_B, r_B
 * ********************************************************
 * auxiliary: value_new == value_old + value_s
 *            rt_cmt
 **********************************************************/
template<typename FieldT>
class commit_gadget : public gadget<FieldT> {
public:
    // Verifier inputs 验证者输入
    pb_variable_array<FieldT> zk_packed_inputs; // 合并为十进制
    pb_variable_array<FieldT> zk_unpacked_inputs; // 拆分为二进制
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker; // 二进制转十进制转换器

    std::shared_ptr<digest_variable<FieldT>> zk_merkle_root; 
    pb_variable<FieldT> value_enforce; // merkle_tree_gadget的参数
    std::shared_ptr<merkle_tree_gadget<FieldT>> witness_input; // merkle_tree_gadget 

    // cmtS = sha256(value_s, pk, sn_s, r_s, sn_A_old, padding)
    pb_variable_array<FieldT> value_s;
    std::shared_ptr<digest_variable<FieldT>> sn_s;    // 256bits serial number associsated with a balance transferred between two accounts
    std::shared_ptr<digest_variable<FieldT>> r_s;     // 256bits random number
    std::shared_ptr<digest_variable<FieldT>> sn_A_old;

    std::shared_ptr<notes_gadget<FieldT>> notes;   //notes
    // new commitment with sha256_three_block_gadget
    std::shared_ptr<digest_variable<FieldT>> cmtS; // cm
    std::shared_ptr<sha256_two_block_gadget<FieldT>> commit_to_input_cmt_s; // note_commitment

    pb_variable<FieldT> ZERO;

    commit_gadget(
        protoboard<FieldT>& pb
    ) : gadget<FieldT>(pb) {
        // Verification
        {
            // The verification inputs are all bit-strings of various
            // lengths (256-bit digests and 64-bit integers) and so we
            // pack them into as few field elements as possible. (The
            // more verification inputs you have, the more expensive
            // verification is.)
            zk_packed_inputs.allocate(pb, verifying_field_element_size()); 
            this->pb.set_input_sizes(verifying_field_element_size());

            alloc_uint256(zk_unpacked_inputs, zk_merkle_root); // 追加merkle_root到zk_unpacked_inputs
            alloc_uint256(zk_unpacked_inputs, sn_s);
            alloc_uint64(zk_unpacked_inputs, this->value_s);

            assert(zk_unpacked_inputs.size() == verifying_input_bit_size()); // 判定输入长度

            // This gadget will ensure that all of the inputs we provide are
            // boolean constrained. 布尔约束 <=> 比特位, 打包
            unpacker.reset(new multipacking_gadget<FieldT>(
                pb,
                zk_unpacked_inputs,
                zk_packed_inputs,
                FieldT::capacity(),
                "unpacker"
            ));
        }

        // Merkle construct
        value_enforce.allocate(pb);

        ZERO.allocate(this->pb, FMT(this->annotation_prefix, "zero"));
        
        r_s.reset(new digest_variable<FieldT>(pb, 256, "random number"));
        sn_A_old.reset(new digest_variable<FieldT>(pb, 256, "serial number"));
        cmtS.reset(new digest_variable<FieldT>(pb, 256, "cmtS"));

        notes.reset(new notes_gadget<FieldT>(
            pb,
            value_s, 
            sn_s,
            r_s,
            sn_A_old
        ));

        commit_to_input_cmt_s.reset(new sha256_two_block_gadget<FieldT>( 
            pb,
            ZERO,
            value_s,       // 64bits value
            sn_s->bits,    // 256bits serial number
            r_s->bits,     // 256bits random number
            sn_A_old->bits,   // 256bits serial number
            cmtS
        ));

        // Merkle construct
        witness_input.reset(new merkle_tree_gadget<FieldT>(
            pb,
            *cmtS,
            *zk_merkle_root,
            value_enforce
        ));
    }

    // 约束函数，为commitment_with_add_and_less_gadget的变量生成约束
    void generate_r1cs_constraints() { 
        // The true passed here ensures all the inputs are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        notes->generate_r1cs_constraints();

        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        // TODO: These constraints may not be necessary if SHA256
        // already boolean constrains its outputs.
        cmtS->generate_r1cs_constraints();
        commit_to_input_cmt_s->generate_r1cs_constraints();

        // Merkle constraint
        zk_merkle_root->generate_r1cs_constraints();
        generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce,"");
        witness_input->generate_r1cs_constraints();
    }

    // 证据函数，为commitment_with_add_and_less_gadget的变量生成证据
    void generate_r1cs_witness(
        const NoteS& note_s, 
        uint256 cmtS_data,
        const uint256& rt,
        const MerklePath& path
    ) {
        notes->generate_r1cs_witness(note_s);

        // Set enforce flag for nonzero input value
        this->pb.val(value_enforce) = (note_s.value != 0) ? FieldT::one() : FieldT::zero();

        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // Witness the commitment of the input note
        commit_to_input_cmt_s->generate_r1cs_witness();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        cmtS->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(cmtS_data)
        );

        // Witness merkle tree authentication path
        witness_input->generate_r1cs_witness(path);

        // Witness rt. This is not a sanity check.
        //
        // This ensures the read gadget constrains
        // the intended root in the event that
        // both inputs are zero-valued.
        zk_merkle_root->bits.fill_with_bits(  // merkle_root填充
            this->pb,
            uint256_to_bool_vector(rt)
        );

        // This happens last, because only by now are all the verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    // 将bit形式的私密输入 打包转换为 域上的元素
    static r1cs_primary_input<FieldT> witness_map(
        const uint256& rt,
        const uint256& sn_s,
        const uint64_t value_s
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, rt);
        insert_uint256(verify_inputs, sn_s);
        insert_uint64(verify_inputs, value_s);

        assert(verify_inputs.size() == verifying_input_bit_size());
        auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        assert(verify_field_elements.size() == verifying_field_element_size());
        return verify_field_elements;
    }

    // 计算输入元素的bit大小
    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        acc += 256; // merkle root
        acc += 256; // sn_s
        acc += 64; // value_s
        
        return acc;
    }

    // 计算域上元素的组数
    static size_t verifying_field_element_size() {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    // 分配空间，打包追加
    void alloc_uint256(
        pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<digest_variable<FieldT>>& var
    ) {
        var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }

    // 分配空间，打包追加
    void alloc_uint160(
        pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<digest_variable<FieldT>>& var
    ) {
        var.reset(new digest_variable<FieldT>(this->pb, 160, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }

    // 分配空间，打包追加
    void alloc_uint64(
        pb_variable_array<FieldT>& packed_into,
        pb_variable_array<FieldT>& integer
    ) {
        integer.allocate(this->pb, 64, "");
        packed_into.insert(packed_into.end(), integer.begin(), integer.end());
    }
};