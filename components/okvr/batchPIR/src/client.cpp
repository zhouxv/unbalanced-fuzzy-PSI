#include "client.h"

// Constructor
Client::Client(PirParams &pir_params) : pir_params_(pir_params)
{

    context_ = new seal::SEALContext(pir_params.get_seal_parameters());
    batch_encoder_ = new seal::BatchEncoder(*context_);
    keygen_ = new seal::KeyGenerator(*context_);
    secret_key_ = keygen_->secret_key();
    encryptor_ = new seal::Encryptor(*context_, secret_key_);
    decryptor_ = new seal::Decryptor(*context_, secret_key_);
    // setting client's public keys
    keygen_->create_galois_keys(gal_keys_);
    keygen_->create_relin_keys(relin_keys_);

    plaint_bit_count_ = pir_params_.get_seal_parameters().plain_modulus().bit_count();
    polynomial_degree_ = pir_params_.get_seal_parameters().poly_modulus_degree();
    num_columns_per_entry_ = pir_params_.get_num_slots_per_entry();
    row_size_ = polynomial_degree_ / 2;
    gap_ = row_size_ / pir_params_.get_dimensions()[0];
    num_databases_ = pir_params_.get_db_count();
}

Client::Client(PirParams &pir_params, seal::KeyGenerator *keygen) : pir_params_(pir_params)
{

    context_ = new seal::SEALContext(pir_params.get_seal_parameters());
    batch_encoder_ = new seal::BatchEncoder(*context_);
    keygen_ = keygen;
    secret_key_ = keygen_->secret_key();
    encryptor_ = new seal::Encryptor(*context_, secret_key_);
    decryptor_ = new seal::Decryptor(*context_, secret_key_);
    // setting client's public keys
    keygen_->create_galois_keys(gal_keys_);
    keygen_->create_relin_keys(relin_keys_);

    plaint_bit_count_ = pir_params_.get_seal_parameters().plain_modulus().bit_count();
    polynomial_degree_ = pir_params_.get_seal_parameters().poly_modulus_degree();
    num_columns_per_entry_ = pir_params_.get_num_slots_per_entry();
    row_size_ = polynomial_degree_ / 2;
    gap_ = row_size_ / pir_params_.get_dimensions()[0];
    num_databases_ = pir_params_.get_db_count();
}

std::pair<seal::GaloisKeys, seal::RelinKeys> Client::get_public_keys()
{
    if (gal_keys_.size() == 0 || relin_keys_.size() == 0)
    {
        std::cerr << "Error: Public keys are not initialized!" << std::endl;
        throw std::runtime_error("Error: Keys are not initialized!");
    }
    return std::make_pair(gal_keys_, relin_keys_);
    ;
}

std::vector<unsigned char> Client::decode_response(PIRResponseList response)
{

    check_noise_budget(response[0]);

    seal::Plaintext pt;
    std::vector<uint64_t> decoded_response;
    std::vector<uint64_t> entry(num_columns_per_entry_, 0ULL);

    for (int i = 0; i < response.size(); i++)
    {
        decryptor_->decrypt(response[i], pt);
        batch_encoder_->decode(pt, decoded_response);

        entry[i] = decoded_response[(entry_slot_ * gap_)];
    }

    // move the entry slot back to 0th slot
    return convert_to_rawdb_entry(entry);
}

void Client::check_noise_budget(const seal::Ciphertext &response)
{
    // Assuming context and secret_key are available
    auto noise_budget = decryptor_->invariant_noise_budget(response);
    if (noise_budget == 0)
    {
        throw std::runtime_error("Error: noise budget is zero");
    }
    cout << "Main: Noise budget left in the response: " << noise_budget << endl;
}

vector<RawResponses> Client::decode_merged_responses(PIRResponseList response, size_t cuckoo_size, vector<vector<uint64_t>> entry_slot_lists)
{
    check_noise_budget(response[0]);
    const size_t num_slots_per_entry = pir_params_.get_num_slots_per_entry();
    const size_t num_slots_per_entry_rounded = utils::next_power_of_two(num_slots_per_entry);
    auto current_slots_fill = gap_ * num_slots_per_entry_rounded;
    size_t remaining_fill = (row_size_ / current_slots_fill);
    size_t num_entries_single_row = row_size_ / num_slots_per_entry_rounded;

    seal::Plaintext pt;
    std::vector<uint64_t> decoded_response;
    size_t remaining_entries = cuckoo_size;
    std::vector<std::vector<uint64_t>> pir_entries(cuckoo_size, std::vector<uint64_t>(num_slots_per_entry_rounded, 0ULL));

    int row_offset = 0;
    for (int k = 0; k < response.size(); k++)
    {
        decoded_response.clear();
        decryptor_->decrypt(response[k], pt);
        batch_encoder_->decode(pt, decoded_response);

        // remaining_fill = (row_size_ / current_slots_fill);
        for (int j = 0; j < remaining_fill; j++)
        {
            // current_slots_fill = gap_ * num_slots_per_entry_rounded;
            int col_offset = j * current_slots_fill;

            // buckets in each bucket set
            for (int l = 0; l < entry_slot_lists[k + j].size(); l++)
            {
                auto tmp = l;

                if (tmp >= gap_)
                {
                    row_offset = row_size_;
                    tmp = tmp - gap_;
                }
                else
                {
                    row_offset = 0;
                }

                // decide the index of ct, then gap offset, then entry within a gap
                int pir_offset = (j * 2 * gap_) + l;

                auto entry_offset = ((entry_slot_lists[k + j][l] * gap_) + tmp);

                // slots for each buckets
                for (int i = 0; i < num_slots_per_entry_rounded; i++)
                {
                    int slot_offset1 = (entry_offset + (i * gap_)) % current_slots_fill;

                    pir_entries[pir_offset][i] = decoded_response[row_offset + col_offset + slot_offset1];
                }
            }
        }
    }

    remaining_entries = cuckoo_size;
    vector<std::vector<std::vector<unsigned char>>> raw_entries_list;

    // loop over the pir_entries list in increments of gap_
    for (int i = 0; i < pir_entries.size(); i += (gap_ * 2))
    {

        // pick number of entries left to parse
        int num_queries = min(remaining_entries, gap_ * 2);
        std::vector<std::vector<unsigned char>> raw_entries(num_queries);

        for (int j = 0; j < num_queries; j++)
        {

            std::vector<uint64_t> input_list(pir_entries[i + j].begin(), pir_entries[i + j].begin() + num_slots_per_entry);
            raw_entries[j] = convert_to_rawdb_entry(input_list);
        }
        remaining_entries -= num_queries;
        raw_entries_list.push_back(raw_entries);
    }

    return raw_entries_list;
}

std::vector<std::vector<unsigned char>> Client::single_pir_decode_responses(PIRResponseList response)
{
    // 取出对应的 entry_slot_list_ 覆盖
    entry_slot_list_ = entry_slot_lists_[slot_list_index];
    slot_list_index += 1;

    auto noise_budget = decryptor_->invariant_noise_budget(response[0]);
    if (noise_budget == 0)
    {
        throw std::runtime_error("Error: noise budget is zero");
    }

    // cout << "Client: noise budget left in the response " << noise_budget << endl;

    auto num_queries = num_databases_;

    seal::Plaintext pt;
    std::vector<uint64_t> decoded_response;
    std::vector<std::vector<uint64_t>> pir_entries(num_queries, std::vector<uint64_t>(num_columns_per_entry_, 0ULL));
    uint64_t idx = 0;

    for (int i = 0; i < response.size(); i++)
    {
        decoded_response.clear();
        decryptor_->decrypt(response[i], pt);
        batch_encoder_->decode(pt, decoded_response);

        for (int j = 0; j < num_queries; j++)
        {
            auto tmp = j;
            if (tmp >= gap_)
            {
                idx = row_size_;
                tmp = tmp - gap_;
            }
            else
            {
                idx = 0;
            }
            pir_entries[j][i] = decoded_response[idx + (entry_slot_list_[j] * gap_) + tmp];
        }
    }

    std::vector<std::vector<unsigned char>> raw_entries(num_queries);
    for (int j = 0; j < num_queries; j++)
    {
        raw_entries[j] = convert_to_rawdb_entry(pir_entries[j]);
    }
    // move the entry    back to 0th slot
    return raw_entries;
}

/**
 * @brief 解码PIR响应并返回原始数据条目。
 *
 * 该函数接收一系列PIR响应并对其进行解码，最后返回原始数据条目。
 *
 * @param response 一个PIR响应列表，每个响应都是加密的。
 * @return 返回一个包含解码数据条目的二维字节数组，每个条目对应一个查询。
 */
RawResponses Client::decode_responses(PIRResponseList response)
{
    // 取出 对应的 entry_slot_list_ 覆盖
    entry_slot_list_ = entry_slot_lists_[slot_list_index];
    slot_list_index += 1;

    // 检查噪声预算，确保解密过程中没有超出预算
    check_noise_budget(response[0]);

    // 查询数量等于数据库数量
    auto num_queries = num_databases_;
    seal::Plaintext pt;
    std::vector<uint64_t> decoded_response;
    // 初始化PIR条目，大小为查询数量和每个条目的列数
    std::vector<std::vector<uint64_t>> pir_entries(num_queries, std::vector<uint64_t>(num_columns_per_entry_, 0ULL));
    uint64_t idx = 0;

    // 最大空槽数量为PIR参数的维度
    const size_t max_empty_slots = pir_params_.get_dimensions()[0];
    size_t remaining_slots_entry = num_columns_per_entry_;

    // 遍历每个响应进行解码
    for (int i = 0; i < response.size(); i++)
    {
        decoded_response.clear();
        // 解密响应并解码为明文数据
        decryptor_->decrypt(response[i], pt);
        batch_encoder_->decode(pt, decoded_response);
        uint32_t loop = std::min(max_empty_slots, remaining_slots_entry);

        // 遍历查询，填充相应的PIR条目
        for (int j = 0; j < num_queries; j++)
        {
            auto tmp = j;
            // 判断是否超出了间隔，调整索引
            if (tmp >= gap_)
            {
                idx = row_size_;
                tmp = tmp - gap_;
            }
            else
            {
                idx = 0;
            }

            // 计算条目的偏移量
            auto entry_offset = ((entry_slot_list_[j] * gap_) + tmp);

            // 遍历每个空槽，填充PIR条目
            for (int k = 0; k < loop; k++)
            {
                // 计算每个chunk的偏移量
                auto chunk_offset = (entry_offset + (k * gap_)) % row_size_;
                pir_entries[j][(i * max_empty_slots) + k] = decoded_response[idx + chunk_offset];
            }
        }

        // 更新剩余槽位数
        remaining_slots_entry -= max_empty_slots;
    }

    // 将解码的PIR条目转换为原始数据库条目
    std::vector<std::vector<unsigned char>> raw_entries(num_queries);
    for (int j = 0; j < num_queries; j++)
    {
        raw_entries[j] = convert_to_rawdb_entry(pir_entries[j]);
    }
    // 返回原始数据条目
    return raw_entries;
}

RawResponses Client::decode_responses_chunks(PIRResponseList response)
{
    // 取出 对应的 entry_slot_list_ 覆盖
    entry_slot_list_ = entry_slot_lists_[slot_list_index];
    slot_list_index += 1;

    check_noise_budget(response[0]);

    auto num_queries = num_databases_;

    seal::Plaintext pt;
    std::vector<uint64_t> decoded_response;
    std::vector<std::vector<uint64_t>> pir_entries(num_queries, std::vector<uint64_t>(num_columns_per_entry_, 0ULL));
    uint64_t row_idx = 0;

    size_t remaining = num_columns_per_entry_;

    for (int i = 0; i < response.size(); i++)
    {
        decoded_response.clear();
        decryptor_->decrypt(response[i], pt);
        batch_encoder_->decode(pt, decoded_response);
        remaining = std::min(pir_params_.get_dimensions()[0], remaining - pir_params_.get_dimensions()[0]);

        for (int j = 0; j < num_queries; j++)
        {
            auto tmp = j;
            if (tmp >= gap_)
            {
                row_idx = row_size_;
                tmp = tmp - gap_;
            }
            else
            {
                row_idx = 0;
            }
            auto start_idx = entry_slot_list_[j];
            for (int k = 0; k < remaining; k++)
            {
                pir_entries[j][k + (i * pir_params_.get_dimensions()[0])] = decoded_response[row_idx + (start_idx + k) * gap_ + tmp];
            }
        }
    }

    std::vector<std::vector<unsigned char>> raw_entries(num_queries);
    for (int j = 0; j < num_queries; j++)
    {
        raw_entries[j] = convert_to_rawdb_entry(pir_entries[j]);
    }
    // move the entry slot back to 0th slot
    return raw_entries;
}

std::vector<unsigned char> Client::convert_to_rawdb_entry(std::vector<uint64_t> input_list)
{
    auto size_of_input = input_list.size();
    const int size_of_coeff = plaint_bit_count_ - 1;
    auto entry_size = pir_params_.get_entry_size();
    std::vector<unsigned char> res(entry_size);
    std::string bit_str;

    for (int i = 0; i < size_of_input; i++)
    {
        for (int j = size_of_coeff - 1; j >= 0; j--)
        {

            char bit = ((input_list[i] >> j) & 1) ? '1' : '0';
            bit_str += bit;
        }
    }

    for (int i = 0; i < entry_size; i++)
    {
        res[i] = std::bitset<8>(bit_str.substr(i * 8, 8)).to_ulong();
    }

    return res;
}

PIRQuery Client::gen_query(vector<uint64_t> indices)
{
    // 检查传入的索引数量是否与数据库数量一致
    if (indices.size() != num_databases_)
    {
        throw std::runtime_error("Error: size of indices should be equal to num_databases_");
    }

    const auto pir_dimensions = pir_params_.get_dimensions(); // 获取PIR参数的维度
    vector<PirDB> plain_queries(indices.size());              // 创建一个平面查询的向量

    entry_slot_list_.clear();
    entry_slot_list_.resize(num_databases_); // 调整条目槽列表的大小

    for (size_t i = 0; i < indices.size(); i++)
    {
        PirDB plain_query(pir_dimensions.size(), std::vector<uint64_t>(polynomial_degree_, 0ULL)); // 初始化平面查询
        uint64_t current_slot = 0;                                                                 // 当前槽的索引

        // 如果索引的值不是默认值，则创建查询
        if (indices[i] != pir_params_.get_default_value())
        {
            auto slot_positions = compute_indices(indices[i]); // 计算索引对应的槽位置
            for (size_t j = 0; j < pir_dimensions.size(); j++)
            {
                // 计算槽索引并设置相应的元素为1
                auto slot_pos = slot_positions[j];                                  // 获取当前维度的槽位置
                auto dim_size = pir_dimensions[0];                                  // 获取维度大小
                const uint64_t rotated_slot = (current_slot + slot_pos) % dim_size; // 计算旋转后的槽索引
                plain_query[j][(rotated_slot * gap_) % row_size_] = 1;              // 设置平面查询的槽
                current_slot = (current_slot + slot_pos) % dim_size;                // 更新当前槽索引
            }
        }

        // 保存第一个块的位置，以便在解码时使用
        entry_slot_list_[i] = current_slot; // 保存当前槽索引
        plain_queries[i] = plain_query;     // 将平面查询存入向量
    }

    entry_slot_lists_.emplace_back(entry_slot_list_);

    return merge_pir_queries(plain_queries); // 合并平面查询并返回
}

PIRQuery Client::merge_pir_queries(vector<PirDB> plain_queries)
{
    const auto pir_dimensions = pir_params_.get_dimensions();

    // Compute the gap and initialize the query object
    PIRQuery merged_query;

    // Initialize the plaintext and the plain query matrix
    seal::Plaintext pt;
    seal::Ciphertext ct;
    PirDB merged_plain_query(pir_dimensions.size(), std::vector<uint64_t>(polynomial_degree_, 0ULL));

    for (int j = 0; j < pir_dimensions.size(); j++)
    {
        for (int i = 0; i < plain_queries.size(); i++)
        {
            auto rotate_amount = i;
            if (i >= gap_)
            {
                plain_queries[i][j] = utils::rotate_vector_col(plain_queries[i][j]);
                rotate_amount = rotate_amount - gap_;
            }
            auto rotated = utils::rotate_vector_row(plain_queries[i][j], rotate_amount);

            for (int k = 0; k < polynomial_degree_; k++)
            {
                merged_plain_query[j][k] = merged_plain_query[j][k] + rotated[k];
            }
        }

        batch_encoder_->encode(merged_plain_query[j], pt);
        encryptor_->encrypt_symmetric(pt, ct);
        merged_query.push_back(ct);
    }

    return merged_query;
}

PIRQuery Client::gen_query(uint64_t index)
{
    // Compute the indices for each dimension
    auto slot_positions = compute_indices(index);
    const auto pir_dimensions = pir_params_.get_dimensions();

    // Check that the dimensions match
    if (pir_dimensions.size() != slot_positions.size())
    {
        throw std::invalid_argument("Error: Dimension mismatch in PIR query.");
    }

    // Compute the gap and initialize the query object
    PIRQuery query;

    // Initialize the plaintext and the plain query matrix
    seal::Plaintext pt;
    seal::Ciphertext ct;
    std::vector<std::vector<uint64_t>> plain_query(pir_dimensions.size(), std::vector<uint64_t>(polynomial_degree_, 0ULL));

    // Construct the query matrix
    uint64_t current_slot = 0;
    for (size_t i = 0; i < pir_dimensions.size(); ++i)
    {

        auto slot_pos = slot_positions[i];
        auto dim_size = pir_dimensions[0];
        // Check that the index is within bounds
        if (slot_pos >= pir_dimensions[i])
        {
            throw std::out_of_range("Error: Index out of range in PIR query.");
        }

        // Calculate the slot index with rotation and set the corresponding element to 1
        const uint64_t rotated_slot = (current_slot + slot_pos) % dim_size;
        plain_query[i][(rotated_slot * gap_) % row_size_] = 1;
        // cout << "Rotated Index for dimension " << i << ": " << slot_pos << endl;

        // Update the rotation for the next dimension
        current_slot = (current_slot + slot_pos) % dim_size;

        // Encrypt the plain query and add it to the query object
        batch_encoder_->encode(plain_query[i], pt);
        encryptor_->encrypt_symmetric(pt, ct);
        query.push_back(ct);
    }

    // Saving the expected slot for entry
    entry_slot_ = current_slot;
    return query;
}

vector<size_t> Client::compute_indices(uint64_t desired_index)
{
    // 检查所需索引是否在范围内
    if (desired_index > pir_params_.get_num_entries() - 1)
    {
        std::cerr << "Error: Desired index " << desired_index << " is out of range (max: " << pir_params_.get_num_entries() << ")" << std::endl;
        throw std::runtime_error("Error: Desired index is out of range");
    }

    auto dimensions = pir_params_.get_dimensions();

    vector<size_t> indices(dimensions.size());

    // 如果维度为3
    if (indices.size() == 3)
    {
        indices[2] = (desired_index / (dimensions[0] * dimensions[1]));                                // 计算第三维索引
        indices[1] = ((desired_index - (indices[2] * dimensions[0] * dimensions[1])) / dimensions[0]); // 计算第二维索引
        indices[0] = (desired_index % dimensions[0]);                                                  // 计算第一维索引
    }
    // 如果维度为2
    else if (indices.size() == 2)
    {
        indices[1] = desired_index / dimensions[0]; // Y轴索引
        indices[0] = desired_index % dimensions[0]; // X轴索引
    }

    // 打印索引
    //  std::cout << "索引: [ ";
    //  for (auto it = indices.begin(); it != indices.end(); it++) {
    //      std::cout << *it << " ";
    //  }
    //  std::cout << "]";
    //  std::cout << std::endl;

    return indices;
}
