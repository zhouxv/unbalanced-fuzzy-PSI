#include "batchpirclient.h"

BatchPIRClient::BatchPIRClient(const BatchPirParams params)
{
    batchpir_params_ = params;
    is_cuckoo_generated_ = false;
    is_map_set_ = false;
    max_attempts_ = batchpir_params_.get_max_attempts();

    prepare_pir_clients();
}

/*
实际的cuckoo hash的插入操作
*/
bool BatchPIRClient::cuckoo_insert(uint64_t key, size_t attempt, std::unordered_map<uint64_t, std::vector<size_t>> key_to_buckets, std::unordered_map<uint64_t, uint64_t> &bucket_to_key)
{
    // 如果尝试次数超过最大尝试次数，抛出异常
    if (attempt > max_attempts_)
    {
        throw std::invalid_argument("Error: Cuckoo hashing failed");
        return false; // 这行代码实际上不会被执行
    }

    // 遍历当前键的候选桶，如果为空的就直接插入，结束
    for (auto v : key_to_buckets[key])
    {
        // 如果桶没有被占用
        if (bucket_to_key.find(v) == bucket_to_key.end())
        {
            bucket_to_key[v] = key; // 将键放入桶中
            return true;            // 插入成功
        }
    }

    // 遍历结束, 都是满的, 获取当前键的候选桶, 随机选一个桶, kick旧的, 重新插入旧的
    std::vector<size_t> candidate_buckets = key_to_buckets[key];
    int idx = rand() % candidate_buckets.size();
    auto picked_bucket = candidate_buckets[idx];
    auto old = bucket_to_key[picked_bucket];
    // 将当前键放入选中的桶中
    bucket_to_key[picked_bucket] = key;

    // 递归调用 cuckoo_insert 以插入旧键
    cuckoo_insert(old, attempt + 1, key_to_buckets, bucket_to_key);
    return true; // 返回插入成功
}

bool BatchPIRClient::cuckoo_hash(vector<uint64_t> batch)
{
    // 如果映射尚未设置，则抛出异常
    if (!is_map_set_)
    {
        throw std::runtime_error("Error: Map is not set");
    }

    // 计算总桶数，桶数由 cuckoo 因子和批量大小决定
    auto total_buckets = ceil(batchpir_params_.get_cuckoo_factor() * batchpir_params_.get_batch_size());
    // 获取数据库条目数量
    auto db_entries = batchpir_params_.get_num_entries();
    // 获取哈希函数的数量
    auto num_candidates = batchpir_params_.get_num_hash_funcs();
    // 获取最大尝试次数
    auto attempts = batchpir_params_.get_max_attempts();

    // 检查批量数据大小是否符合预期
    if (batch.size() != batchpir_params_.get_batch_size())
    {
        cout << batch.size() << " " << batchpir_params_.get_batch_size() << " " << endl;
        throw std::invalid_argument("Error: Batch size is wrong");
    }

    // 调整 cuckoo 表大小，大小由批量大小和 cuckoo 因子决定
    cuckoo_table_.clear();
    cuckoo_table_.resize(std::ceil(batchpir_params_.get_batch_size() * batchpir_params_.get_cuckoo_factor()), batchpir_params_.get_default_value());

    // auto cuckooTable = cuckooTables.back();

    // 构建一个从 数据库索引 到 候选桶的索引 的映射, key 为数据库索引, value 为候选桶的索引
    std::unordered_map<uint64_t, std::vector<size_t>> key_to_buckets;

    for (auto v : batch)
    {
        // 获取候选桶
        auto candidates = utils::get_candidate_buckets(v, num_candidates, total_buckets);
        key_to_buckets[v] = candidates;
    }

    // 用于存储桶与键的映射
    std::unordered_map<uint64_t, uint64_t> bucket_to_key;

    // 用当前时间作为种子初始化随机数生成器
    srand(time(nullptr));

    // 对每个键执行 cuckoo 插入操作
    for (auto const &[key, value] : key_to_buckets)
    {
        cuckoo_insert(key, 0, key_to_buckets, bucket_to_key);
    }

    // 将最终的 <key 桶的位置, value 数据库中的位置> 的映射应用到 cuckoo 表
    for (auto const &[key, value] : bucket_to_key)
    {
        cuckoo_table_[key] = value;
    }

    cuckooTables.emplace_back(cuckoo_table_);

    // 清空临时数据结构
    bucket_to_key.clear();
    key_to_buckets.clear();

    // 标记 cuckoo 哈希已生成
    is_cuckoo_generated_ = true;

    // 执行 cuckoo 表的转换
    translate_cuckoo();
    return true;
}

void BatchPIRClient::translate_cuckoo()
{
    // 如果映射未设置或 cuckoo 哈希表未生成，抛出异常
    if (!is_map_set_ || !is_cuckoo_generated_)
    {
        throw std::runtime_error("Error: Cannot translate the data because either the map has not been set or the cuckoo hash table has not been generated.");
    }

    auto num_buckets = cuckoo_table_.size(); // 获取 cuckoo 表的桶数
    for (int i = 0; i < num_buckets; i++)
    {
        // 检查桶是否为空
        if (cuckoo_table_[i] != batchpir_params_.get_default_value())
        {
            // 将数据库索引转换为桶索引
            // cuckoo_table_[i]中本来为数据库索引
            // map中，数据库位置 和 桶位置 为 key, 在服务器中 buckets_[b] 中的位置为 value
            cuckoo_table_[i] = map_[to_string(cuckoo_table_[i]) + to_string(i)];
            // 处理后，cuckoo_table_[i]为查询的索引在第i个桶的具体位置

            // std::cout << "i" << i << "cuckoo_table_[i]" << cuckoo_table_[i] << std::endl;
        }
    }
}

vector<PIRQuery> BatchPIRClient::create_queries(vector<uint64_t> batch)
{
    // 如果批量大小与预期的批量大小不符，抛出异常
    if (batch.size() != batchpir_params_.get_batch_size())
        throw std::runtime_error("Error: batch is not selected size");

    // 调用 cuckoo_hash 方法生成 cuckoo 哈希表
    cuckoo_hash(batch);
    vector<PIRQuery> queries;

    // 获取参数：最大桶大小，条目大小，维度大小等
    size_t max_bucket_size = batchpir_params_.get_max_bucket_size();
    size_t entry_size = batchpir_params_.get_entry_size();
    size_t dim_size = batchpir_params_.get_first_dimension_size();
    auto max_slots = batchpir_params_.get_seal_parameters().poly_modulus_degree();
    auto num_buckets = cuckoo_table_.size();                      // 获取 cuckoo 表的桶数
    size_t per_server_capacity = max_slots / dim_size;            // 每个服务器的最大容量
    size_t num_servers = ceil(num_buckets / per_server_capacity); // 计算需要多少个服务器

    // 初始化桶的索引
    auto previous_idx = 0;
    // 对每个客户端生成查询
    for (int i = 0; i < client_list_.size(); i++)
    {
        // 计算当前客户端的桶范围
        const size_t offset = std::min(per_server_capacity, num_buckets - previous_idx);
        vector<uint64_t> sub_buckets(cuckoo_table_.begin() + previous_idx, cuckoo_table_.begin() + previous_idx + offset);
        previous_idx += offset; // 更新已处理的桶的索引

        // 为当前客户端生成查询
        auto query = client_list_[i].gen_query(sub_buckets);
        measure_size(query, 2);   // 测量查询的大小
        queries.push_back(query); // 将查询添加到结果列表
    }

    // 返回生成的查询列表
    return queries;
}

// todo: 需修改以适应新的哈希表
bool BatchPIRClient::cuckoo_hash_witout_checks(vector<uint64_t> batch)
{

    auto total_buckets = ceil(batchpir_params_.get_cuckoo_factor() * batchpir_params_.get_batch_size());
    auto db_entries = batchpir_params_.get_num_entries();
    auto num_candidates = batchpir_params_.get_num_hash_funcs();
    auto attempts = batchpir_params_.get_max_attempts();

    if (batch.size() != batchpir_params_.get_batch_size())
    {
        cout << batch.size() << " " << batchpir_params_.get_batch_size() << " " << endl;
        throw std::invalid_argument("Error: Batch size is wrong");
    }

    cuckoo_table_.resize(std::ceil(batchpir_params_.get_batch_size() * batchpir_params_.get_cuckoo_factor()), batchpir_params_.get_default_value());

    std::unordered_map<uint64_t, std::vector<size_t>> key_to_buckets;
    for (auto v : batch)
    {
        auto candidates = utils::get_candidate_buckets(v, num_candidates, total_buckets);
        key_to_buckets[v] = candidates;
    }
    std::unordered_map<uint64_t, uint64_t> bucket_to_key;

    // seed the random number generator with current time
    srand(time(nullptr));
    for (auto const &[key, value] : key_to_buckets)
    {
        cuckoo_insert(key, 0, key_to_buckets, bucket_to_key);
    }

    for (auto const &[key, value] : bucket_to_key)
    {
        cuckoo_table_[key] = value;
    }

    bucket_to_key.clear();
    key_to_buckets.clear();

    is_cuckoo_generated_ = true;

    // translate_cuckoo();
    return true;
}

void BatchPIRClient::measure_size(vector<Ciphertext> list, size_t seeded)
{

    for (int i = 0; i < list.size(); i++)
    {
        serialized_comm_size_ += ceil(list[i].save_size() / seeded);
    }
}

size_t BatchPIRClient::get_serialized_commm_size()
{
    return ceil(serialized_comm_size_ / 1024);
}

void BatchPIRClient::set_map(std::unordered_map<std::string, uint64_t> map)
{
    map_ = map;
    is_map_set_ = true;
}

void BatchPIRClient::prepare_pir_clients()
{
    size_t max_bucket_size = batchpir_params_.get_max_bucket_size(); // 获取最大桶大小
    size_t entry_size = batchpir_params_.get_entry_size();           // 获取条目大小

    size_t dim_size = batchpir_params_.get_first_dimension_size();                                     // 获取维度大小
    auto max_slots = batchpir_params_.get_seal_parameters().poly_modulus_degree();                     // 获取最大槽数
    auto num_buckets = ceil(batchpir_params_.get_batch_size() * batchpir_params_.get_cuckoo_factor()); // 计算桶的数量
    size_t per_client_capacity = max_slots / dim_size;                                                 // 每个客户端的最大容量
    size_t num_client = ceil(num_buckets / per_client_capacity);                                       // 计算需要多少个客户端
    auto remaining_buckets = num_buckets;                                                              // 剩余的桶数
    auto previous_idx = 0;                                                                             // 之前的索引
    seal::KeyGenerator *keygen;                                                                        // 密钥生成器指针

    for (int i = 0; i < num_client; i++) // 对每个客户端进行循环
    {
        const size_t num_dbs = std::min(per_client_capacity, static_cast<size_t>(num_buckets - previous_idx));    // 计算当前客户端的数据库数量
        previous_idx += num_dbs;                                                                                  // 更新已处理的桶的索引
        PirParams params(max_bucket_size, entry_size, num_dbs, batchpir_params_.get_seal_parameters(), dim_size); // 创建 PIR 参数
        if (i == 0)                                                                                               // 如果是第一个客户端
        {
            Client client(params);          // 创建客户端
            client_list_.push_back(client); // 将客户端添加到列表
            keygen = client.get_keygen();   // 获取密钥生成器
        }
        else // 如果不是第一个客户端
        {
            Client client(params, keygen);  // 使用相同的密钥生成器创建客户端
            client_list_.push_back(client); // 将客户端添加到列表
        }
    }
}

vector<RawDB> BatchPIRClient::decode_responses(vector<PIRResponseList> responses)
{
    vector<std::vector<std::vector<unsigned char>>> entries_list;
    for (int i = 0; i < responses.size(); i++)
    {
        std::vector<std::vector<unsigned char>> entries = client_list_[i].decode_responses(responses[i]);
        entries_list.push_back(entries);
    }
    return entries_list;
}

vector<RawDB> BatchPIRClient::decode_responses_chunks(PIRResponseList responses)
{
    vector<std::vector<std::vector<unsigned char>>> entries_list;                             // 创建一个存储条目的列表
    const size_t num_slots_per_entry = batchpir_params_.get_num_slots_per_entry();            // 获取每个条目的槽数
    const size_t num_slots_per_entry_rounded = utils::next_power_of_two(num_slots_per_entry); // 将槽数向上取整为2的幂
    const size_t max_empty_slots = batchpir_params_.get_first_dimension_size();               // 获取最大空槽数
    const size_t row_size = batchpir_params_.get_seal_parameters().poly_modulus_degree() / 2; // 获取行大小
    const size_t gap = row_size / max_empty_slots;                                            // 计算每个槽之间的间隔

    measure_size(responses, 1); // 测量响应的大小

    auto current_fill = gap * num_slots_per_entry_rounded; // 计算当前填充
    size_t num_buckets_merged = (row_size / current_fill); // 计算合并的桶数

    /*
    ceil(num_slots_per_entry * 1.0 / max_empty_slots) > 1：这个条件计算 num_slots_per_entry 除以 max_empty_slots 的值，并向上取整（使用 ceil 函数）。如果结果大于 1，说明每个条目所需的槽位数量超过了最大空槽位数。
    num_buckets_merged <= 1：这个条件检查合并的桶的数量是否小于或等于 1。如果是，说明没有足够的桶进行合并，可能会影响后续的处理。
    client_list_.size() == 1：这个条件检查客户端列表的大小是否等于 1。如果只有一个客户端，可能意味着没有足够的并发处理能力。
     */
    if (ceil(num_slots_per_entry * 1.0 / max_empty_slots) > 1 || num_buckets_merged <= 1 || client_list_.size() == 1) // 检查条件
    {
        std::cout << "decode_responses_chunks not merge" << std::endl;
        size_t num_chunk_ctx = ceil((num_slots_per_entry * 1.0) / max_empty_slots); // 计算每个块的上下文数量

        for (int i = 0; i < client_list_.size(); i++) // 对每个客户端进行循环
        {
            auto start_idx = (i * num_chunk_ctx);                                                                    // 计算起始索引
            PIRResponseList subvector(responses.begin() + start_idx, responses.begin() + start_idx + num_chunk_ctx); // 获取子向量
            std::vector<std::vector<unsigned char>> entries = client_list_[i].decode_responses(subvector);           // 解码响应
            entries_list.push_back(entries);                                                                         // 将条目添加到列表中
        }
    }
    else // 如果条件不满足
    {
        std::cout << "decode_responses_chunks merge" << std::endl;
        vector<vector<uint64_t>> entry_slot_lists;    // 创建条目槽列表
        for (int i = 0; i < client_list_.size(); i++) // 对每个客户端进行循环
        {
            entry_slot_lists.push_back(client_list_[i].get_entry_list()); // 获取条目列表
        }

        entries_list = client_list_[0].decode_merged_responses(responses, cuckoo_table_.size(), entry_slot_lists); // 解码合并响应
    }
    return entries_list; // 返回条目列表
}

std::pair<seal::GaloisKeys, seal::RelinKeys> BatchPIRClient::get_public_keys()
{
    std::pair<seal::GaloisKeys, seal::RelinKeys> keys;
    keys = client_list_[0].get_public_keys();
    return keys;
}