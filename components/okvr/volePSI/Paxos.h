#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 

#include <cassert>
#include <vector>
#include <algorithm>
#include <ostream>
#include <memory>
#include <numeric>
#include <iomanip>
#include <cmath>

#include "volePSI/Defines.h"

#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "volePSI/PxUtil.h"

namespace volePSI
{
	struct PaxosParam {

		// the type of dense columns.
		// 稠密列的类型。
		enum DenseType
		{
			Binary,
			GF128
		};

		u64 mSparseSize = 0,
			mDenseSize = 0,
			mWeight = 0,
			mG = 0,
			mSsp = 40;
		DenseType mDt = GF128;

		PaxosParam() = default;
		PaxosParam(const PaxosParam&) = default;
		PaxosParam& operator=(const PaxosParam&) = default;

		PaxosParam(u64 numItems, u64 weight = 3, u64 ssp = 40, DenseType dt = DenseType::GF128)
		{
			init(numItems, weight, ssp, dt);
		}

		// computes the paxos parameters based the parameters.
		// 根据参数计算Paxos参数。
		void init(u64 numItems, u64 weight = 3, u64 ssp = 40, DenseType dt = DenseType::GF128);

		// the size of the paxos data structure.
		// Paxos数据结构的大小。
		u64 size() const
		{
			return mSparseSize + mDenseSize;
		}
	};

	// The core Paxos algorithm. The template parameter
	// IdxType should be in {u8,u16,u32,u64} and large
	// enough to fit the paxos size value.
	// 核心Paxos算法。模板参数IdxType应为{u8,u16,u32,u64}中的一种，并且足够大以适应Paxos大小值。
	template<typename IdxType>
	class Paxos : public PaxosParam, public oc::TimerAdapter
	{
	public:

		// the number of items to be encoded.
		// 要编码的项目数量。
		IdxType mNumItems = 0;

		// the encoding/decoding seed.
		// 编码/解码种子。
		block mSeed;

		bool mVerbose = false;
		bool mDebug = false;

		// when decoding, add the decoded value to the 
		// output, as opposed to overwriting.
		// 解码时，将解码值添加到输出，而不是覆盖。
		bool mAddToDecode = false;

		// the method for generating the row data based on the input value.
		// 基于输入值生成行数据的方法。
		PaxosHash<IdxType> mHasher;

		// an allocate used for the encoding algorithm
		// 用于编码算法的分配。
		std::unique_ptr<u8[]> mAllocation;
		u64 mAllocationSize = 0;

		// The dense part of the paxos matrix
		// Paxos矩阵的稠密部分
		span<block> mDense;

		// The sparse part of the paxos matrix
		// Paxos矩阵的稀疏部分
		MatrixView<IdxType> mRows;

		// the sparse columns of the matrix
		// 矩阵的稀疏列
		span<span<IdxType>> mCols;

		// the memory used to store the column data.
		// 用于存储列数据的内存。
		span<IdxType> mColBacking;

		// A data structure used to track the current weight of the rows.
		// 用于跟踪行当前权重的数据结构。
		WeightData<IdxType> mWeightSets;

		Paxos() = default;
		Paxos(const Paxos&) = default;
		Paxos(Paxos&&) = default;
		Paxos& operator=(const Paxos&) = default;
		Paxos& operator=(Paxos&&) = default;

		// initialize the paxos with the given parameters.
		// 使用给定参数初始化Paxos。
		void init(u64 numItems, u64 weight, u64 ssp, PaxosParam::DenseType dt, block seed)
		{
			PaxosParam p(numItems, weight, ssp, dt);
			init(numItems, p, seed);
		}

		// initialize the paxos with the given parameters.
		// 使用给定参数初始化Paxos, 提供种子
		void init(u64 numItems, PaxosParam p, block seed);

		// solve/encode the given inputs,value pair. The paxos data 
		// structure is written to output. input,value should be numItems 
		// in size, output should be Paxos::size() in size. If the paxos
		// should be randomized, then provide a PRNG.
		// solve/编码给定的输入值对。Paxos数据结构写入输出。input,value 应为numItems大小，输出应为Paxos::size()大小。如果Paxos应随机化，则提供PRNG。
		template<typename ValueType>
		void solve(span<const block> inputs, span<const ValueType> values, span<ValueType> output, oc::PRNG* prng = nullptr)
		{
			setInput(inputs);
			encode<ValueType>(values, output, prng);
		}

		// solve/encode the given inputs,value pair. The paxos data 
		// structure is written to output. input,value should have numItems 
		// rows, output should have Paxos::size() rows. All should have the 
		// same number of columns. If the paxos should be randomized, then 
		// provide a PRNG.
		// 解决/编码给定的输入、值对。Paxos数据结构写入输出。输入、值应具有numItems行，输出应具有Paxos::size()行。所有应具有相同数量的列。如果Paxos应随机化，则提供PRNG。
		template<typename ValueType>
		void solve(span<const block> inputs, MatrixView<const ValueType> values, MatrixView<ValueType> output, oc::PRNG* prng = nullptr)
		{
			setInput(inputs);
			encode<ValueType>(values, output, prng);

			if(mDebug)
				check(inputs, values, output);
		}

		// set the input keys which define the paxos matrix. After that,
		// encode can be called more than once.
		// 设置定义Paxos矩阵的输入密钥。之后，可以多次调用编码。
		// 将输入数据转化为稀疏矩阵的行列表示，并对列的权重进行统计和重建
		void setInput(span<const block> inputs);

		// encode the given inputs,value pair based on the already set input. The paxos data 
		// structure is written to output. input,value should be numItems 
		// in size, output should be Paxos::size() in size. If the paxos
		// should be randomized, then provide a PRNG.
		// 根据已设置的输入编码给定的输入、值对。Paxos数据结构写入输出。输入、值应为numItems大小，输出应为Paxos::size()大小。如果Paxos应随机化，则提供PRNG。
		template<typename ValueType>
		void encode(span<const ValueType> values, span<ValueType> output, oc::PRNG* prng = nullptr)
		{
			PxVector<const ValueType> V(values);
			PxVector<ValueType> P(output);
			auto h = P.defaultHelper();
			encode(V, P, h, prng);
		}

		// encode the given inputs,value pair based on the already set input. The paxos data 
		// structure is written to output. input,value should have numItems 
		// rows, output should have Paxos::size() rows. All should have the 
		// same number of columns. If the paxos should be randomized, then 
		// provide a PRNG.
		// 根据已设置的输入编码给定的输入、值对。Paxos数据结构写入输出。输入、值应具有numItems行，输出应具有Paxos::size()行。所有应具有相同数量的列。如果Paxos应随机化，则提供PRNG。
		template<typename ValueType>
		void encode(MatrixView<const ValueType> values, MatrixView<ValueType> output, oc::PRNG* prng = nullptr)
		{
			if (values.cols() != output.cols())
				throw RTE_LOC;

			if (values.cols() == 1)
			{
				// reduce matrix to span if possible.
				// 如果可能，将矩阵简化为span。
				encode(span<const ValueType>(values), span<ValueType>(output), prng);
			}
			else if (
				values.cols() * sizeof(ValueType) % sizeof(block) == 0 && 
				std::is_same<ValueType, block>::value == false)
			{
				// reduce ValueType to block if possible.
				// 如果可能，将ValueType简化为block。
				auto n = values.rows();
				auto m = values.cols() * sizeof(ValueType) / sizeof(block);

				encode<block>(
					MatrixView<const block>((block*)values.data(), n, m), 
					MatrixView<block>((block*)output.data(), n, m),
					prng);
			}
			else
			{
				PxMatrix<const ValueType> V(values);
				PxMatrix<ValueType> P(output);
				auto h = P.defaultHelper();
				encode(V, P, h, prng);
			}
		}

		// encode the given input with the given paxos p. Vec and ConstVec should
		// meet the PxVector concept... Helper used to perform operations on values.
		// 使用给定的Paxos p编码给定输入。Vec和ConstVec应符合PxVector概念... Helper用于对值执行操作。
		template<typename Vec, typename ConstVec, typename Helper>
		void encode(ConstVec& values, Vec& output, Helper& h, oc::PRNG* prng = nullptr);

		// Decode the given input based on the data paxos structure p. The
		// output is written to values.
		// 根据数据Paxos结构p解码给定输入。输出写入值。
		template<typename ValueType>
		void decode(span<const block> input, span<ValueType> values, span<const ValueType> p);

		// Decode the given input based on the data paxos structure p. The
		// output is written to values. values and p should have the same 
		// number of columns.
		// 根据数据Paxos结构p解码给定输入。输出写入值。values和p应具有相同数量的列。
		template<typename ValueType>
		void decode(span<const block> input, MatrixView<ValueType> values, MatrixView<const ValueType> p);

		// decode the given input with the given paxos p. Vec and ConstVec should
		// meet the PxVector concept... Helper used to perform operations on values.
		// 使用给定的Paxos p解码给定输入。Vec和ConstVec应符合PxVector概念... Helper用于对值执行操作。
		template<typename Helper, typename Vec, typename ConstVec>
		void decode(span<const block> input, Vec& values, ConstVec& p, Helper& h);

		struct Triangulization
		{
			PaxosPermutation<IdxType> mPerm;
			u64 mGap = 0;
			oc::SparseMtx mH;

			oc::SparseMtx getA() const;
			oc::SparseMtx getC() const;
			oc::SparseMtx getB() const;
			oc::SparseMtx getD() const;
			oc::SparseMtx getE() const;
			oc::SparseMtx getF() const;
		};

		// returns a printable version of the paxos matrix after
		// being triangulized. setInput(...) should be called first.
		// 返回三角化后的Paxos矩阵的可打印版本。应首先调用setInput(...)。
		Triangulization getTriangulization();

		////////////////////////////////////////
		// private functions
		////////////////////////////////////////

		// allocate the memory needed to triangulate.
		// 分配三角化所需的内存。
		void allocate();

		// decodes 32 instances. rows should contain the row indices, dense the dense 
		// part. values is where the values are written to. p is the Paxos, h is the value op. helper.
		// 解码32个实例。rows应包含行索引，dense为稠密部分。values是写入值的地方。p是Paxos，h是值操作助手。
		template<typename ValueType, typename Helper, typename Vec>
		void decode32(const IdxType* rows, const block* dense, ValueType* values, Vec& p, Helper& h);

		// decodes 8 instances. rows should contain the row indices, dense the dense 
		// part. values is where the values are written to. p is the Paxos, h is the value op. helper.
		// 解码8个实例。rows应包含行索引，dense为稠密部分。values是写入值的地方。p是Paxos，h是值操作助手。
		template<typename ValueType, typename Helper, typename Vec>
		void decode8(const IdxType* rows, const block* dense, ValueType* values, Vec& p, Helper& h);

		// decodes one instance. rows should contain the row indices, dense the dense 
		// part. values is where the values are written to. p is the Paxos, h is the value op. helper.
		// 解码一个实例。rows应包含行索引，dense为稠密部分。values是写入值的地方。p是Paxos，h是值操作助手。
		template<typename ValueType, typename Helper, typename Vec>
		void decode1(
			const IdxType* rows,
			const block* dense,
			ValueType* values,
			Vec& p,
			Helper& h);

		// manually set the row indices and the dense values.
		// 手动设置行索引和稠密值
		void setInput(MatrixView<IdxType> rows, span<block> dense);

		// manually set the row indices and the dense values. In 
		// addition, provide the memory that is needed to perform
		// encoding.
		// 手动设置行索引和稠密值。此外，提供执行编码所需的内存
		void setInput(
			MatrixView<IdxType> rows,
			span<block> dense,
			span<span<IdxType>> cols,
			span<IdxType> colBacking,
			span<IdxType> colWeights);

		// perform the triangulization algorithm for encoding. This
		// populates mainRows, mainCols with the rows/columns of C
		// gapRows are all the rows that are in the gap.
		// 执行用于编码的三角化算法。这填充mainRows、mainCols与C的行/列，gapRows是所有在间隙中的行。
		void triangulate(
			std::vector<IdxType>& mainRows,
			std::vector<IdxType>& mainCols,
			std::vector<std::array<IdxType, 2>>& gapRows);

		// once triangulated, this is used to assign values 
		// to output (paxos).
		// 一旦三角化，这用于将值分配给输出（Paxos）。
		template<typename Vec, typename ConstVec, typename Helper>
		void backfill(
			span<IdxType> mainRows,
			span<IdxType> mainCols,
			span<std::array<IdxType, 2>> gapRows,
			ConstVec& values,
			Vec& output,
			Helper& h,
			oc::PRNG* prng);

		// once triangulated, this is used to assign values 
		// to output (paxos). Use the gf128 dense algorithm.
		// 一旦三角化，这用于将值分配给输出（Paxos）。使用gf128稠密算法。
		template<typename Vec, typename ConstVec, typename Helper>
		void backfillGf128(
			span<IdxType> mainRows,
			span<IdxType> mainCols,
			span<std::array<IdxType, 2>> gapRows,
			ConstVec& values,
			Vec& output,
			Helper& h,
			oc::PRNG* prng);

		// once triangulated, this is used to assign values 
		// to output (paxos). Use the classic binary dense algorithm.
		// 一旦三角化，这用于将值分配给输出（Paxos）。使用经典的二进制稠密算法。
		template<typename Vec, typename ConstVec, typename Helper>
		void backfillBinary(
			span<IdxType> mainRows,
			span<IdxType> mainCols,
			span<std::array<IdxType, 2>> gapRows,
			ConstVec& values,
			Vec& output,
			Helper& h,
			oc::PRNG* prng);

		// helper function used for getTriangulization();
		// 用于getTriangulization()的辅助函数。
		std::pair<PaxosPermutation<IdxType>, u64> computePermutation(
			span<IdxType> mainRows,
			span<IdxType> mainCols,
			span<std::array<IdxType, 2>> gapRows,
			bool withDense);
		
		// helper function used for getTriangulization(); returns
		// the rows/columns permuted by perm.
		// 用于getTriangulization()的辅助函数；返回由perm排列的行/列。
		oc::SparseMtx getH(PaxosPermutation<IdxType>& perm) const;

		// helper function that generates the column data given that 
		// the row data has been populated (via setInput(...)).
		// 辅助函数，根据已填充的行数据（通过setInput(...)）生成列数据。
		void rebuildColumns(span<IdxType> colWeights, u64 totalWeight);

		// A sparse representation of the F * C^-1 matrix.
		// F * C^-1矩阵的稀疏表示。
		struct FCInv
		{
			FCInv(u64 n)
				: mMtx(n)
			{}
			std::vector<std::vector<IdxType>> mMtx;
		};

		// returns the sparse representation of the F * C^-1 matrix.
		// 返回F * C^-1矩阵的稀疏表示。
		FCInv getFCInv(
			span<IdxType> mainRows,
			span<IdxType> mainCols,
			span<std::array<IdxType, 2>> gapRows) const;

		// returns which columns are used for the gap. This
		// is only used for binary dense method.
		// 返回用于间隙的列。这仅用于二进制稠密方法。
		std::vector<u64> getGapCols(
			FCInv& fcinv,
			span<std::array<IdxType, 2>> gapRows) const;

		// returns x2' = x2 - D' r - FC^-1 x1
		// 返回x2' = x2 - D' r - FC^-1 x1
		template<typename Vec, typename ConstVec, typename Helper>
		Vec getX2Prime(
			FCInv &fcinv,
			span<std::array<IdxType, 2>> gapRows, 
			span<u64> gapCols,
			const ConstVec& X,
			const Vec& P,
			Helper& h);

		// returns E' = -FC^-1B + E
		// 返回E' = -FC^-1B + E
		oc::DenseMtx getEPrime(
			FCInv &fcinv,
			span<std::array<IdxType, 2>> gapRows,
			span<u64> gapCols);

		template<typename Vec, typename Helper>
		void randomizeDenseCols(Vec&, Helper&, span<u64> gapCols, oc::PRNG* prng);

		template<typename ValueType>
		void check(span<const block> inputs, MatrixView<const ValueType> values, MatrixView<const ValueType> output)
		{
			oc::Matrix<ValueType> v2(values.rows(), values.cols());
			decode<ValueType>(inputs, v2, output);

			for (u64 i = 0; i < values.rows(); ++i)
			{
				for(u64 j =0; j < values.cols(); ++j)
					if (v2(i, j) != values(i, j))
					{
						std::cout << "paxos failed to encode. \n"
							<< "inputs["<< i << "]" << inputs[i] << "\n"
							<< "seed " << mSeed  <<"\n"
							<< "n " << size() << "\n"
							<< "m " << inputs.size() << "\n"
							<< std::endl;
						throw RTE_LOC;
					}
			}
		}

	};

	// a binned version of paxos. Internally calls paxos.
	// Paxos的一个分箱版本。内部调用Paxos。
	class Baxos
	{
	public:
		u64 mNumItems = 0, mNumBins = 0, mItemsPerBin = 0, mWeight = 0, mSsp = 0;

		// the parameters used on a single bin.
		// 用于单个箱的参数。
		PaxosParam mPaxosParam;
		block mSeed;

		bool mDebug = false;

		// when decoding, add the decoded value to the 
		// output, as opposed to overwriting.
		// 解码时，将解码值添加到输出，而不是覆盖。
		bool mAddToDecode = false;

		// initialize the paxos with the given parameter.
		// 使用给定参数初始化Paxos。
		void init(u64 numItems, u64 binSize, u64 weight, u64 ssp, PaxosParam::DenseType dt, block seed)
		{
			mNumItems = numItems;
			mWeight = weight;
			mNumBins = (numItems + binSize - 1) / binSize;
			mItemsPerBin = getBinSize(mNumBins, mNumItems, ssp + std::log2(mNumBins));
			mSsp = ssp;
			mSeed = seed;
			mPaxosParam.init(mItemsPerBin, weight, ssp, dt);
		}

		// solve the system for the given input vectors.
		// inputs are the keys
		// values are the desired values that inputs should decode to.
		// output is the paxos.
		// prng should be non-null if randomized paxos is desired.
		// 为给定输入向量解决系统。
		// inputs是密钥
		// values是输入应解码为的期望值。
		// output是Paxos。
		// 如果希望随机化Paxos，则prng应为非空。
		template<typename ValueType>
		void solve(
			span<const block> inputs,
			span<const ValueType> values,
			span<ValueType> output,
			oc::PRNG* prng = nullptr,
			u64 numThreads = 0);

		// solve the system for the given input matrices.
		// inputs are the keys
		// values are the desired values that inputs should decode to.
		// output is the paxos.
		// prng should be non-null if randomized paxos is desired.
		// 为给定输入矩阵解决系统。
		// inputs是密钥
		// values是输入应解码为的期望值。
		// output是Paxos。
		// 如果希望随机化Paxos，则prng应为非空。
		template<typename ValueType>
		void solve(
			span<const block> inputs,
			MatrixView<const ValueType> values,
			MatrixView<ValueType> output,
			oc::PRNG* prng = nullptr,
			u64 numThreads = 0);

		// solve/encode the system.
		// 解决/编码系统。
		template<typename Vec, typename ConstVec, typename Helper>
		void solve(
			span<const block> inputs,
			ConstVec& values,
			Vec& output,
			oc::PRNG* prng,
			u64 numThreads,
			Helper& h);

		// decode a single input given the paxos p.
		// 解码给定Paxos p的单个输入。
		template<typename ValueType>
		ValueType decode(const block& input, span<const ValueType> p)
		{
			ValueType r;
			decode(span<const block>(&input, 1), span<ValueType>(&r, 1), p);
			return r;
		}

		// decode the given input vector and write the result to values.
		// inputs are the keys.
		// values are the output.
		// p is the paxos vector.
		// 解码给定输入向量并将结果写入值。
		// inputs是密钥。
		// values是输出。
		// p是Paxos向量。
		template<typename ValueType>
		void decode(span<const block> input, span<ValueType> values, span<const ValueType> p, u64 numThreads = 0);

		// decode the given input matrix and write the result to values.
		// inputs are the keys.
		// values are the output.
		// p is the paxos matrix.
		// 解码给定输入矩阵并将结果写入值。
		// inputs是密钥。
		// values是输出。
		// p是Paxos矩阵。
		template<typename ValueType>
		void decode(span<const block> input, MatrixView<ValueType> values, MatrixView<const ValueType> p, u64 numThreads = 0);

		template<typename Vec, typename ConstVec, typename Helper>
		void decode(
			span<const block> inputs,
			Vec& values,
			ConstVec& p,
			Helper& h,
			u64 numThreads);

		//////////////////////////////////////////
		// private impl
		//////////////////////////////////////////

		// solve/encode the system.
		// 解决/编码系统。
		template<typename IdxType, typename Vec, typename ConstVec, typename Helper>
		void implParSolve(
			span<const block> inputs,
			ConstVec& values,
			Vec& output,
			oc::PRNG* prng,
			u64 numThreads,
			Helper& h);

		// create the desired number of threads and split up the work.
		// 创建所需数量的线程并分配工作。
		template<typename IdxType, typename Vec, typename ConstVec, typename Helper>
		void implParDecode(
			span<const block> inputs,
			Vec& values,
			ConstVec& p,
			Helper& h,
			u64 numThreads);

		// decode the given inputs based on the paxos p. The output is written to values.
		// 根据Paxos p解码给定输入。输出写入值。
		template<typename IdxType, typename Vec, typename ConstVec, typename Helper>
		void implDecodeBatch(span<const block> inputs, Vec& values, ConstVec& p, Helper& h);

		// decode the given inputs based on the paxos p. The output is written to values.
		// this differs from implDecode in that all inputs must be for the same paxos bin.
		// 根据Paxos p解码给定输入。输出写入值。
		// 这与implDecode不同，因为所有输入必须属于同一个Paxos箱。
		template<typename IdxType, typename Vec, typename ConstVec, typename Helper>
		void implDecodeBin(
			u64 binIdx,
			span<block> hashes,
			Vec& values,
			Vec& valuesBuff,
			span<u64> inIdxs,
			ConstVec& p,
			Helper& h,
			Paxos<IdxType>& paxos);

		// the size of the paxos.
		// Paxos的大小。
		u64 size()
		{
			return u64(mNumBins * (mPaxosParam.mSparseSize + mPaxosParam.mDenseSize));
		}

		static u64 getBinSize(u64 numBins, u64 numItems, u64 ssp);

		u64 binIdxCompress(const block& h)
		{
			return (h.get<u64>(0) ^ h.get<u64>(1) ^ h.get<u32>(3));
		}

		u64 modNumBins(const block& h)
		{
			return binIdxCompress(h) % mNumBins;
		}

		template<typename Vec, typename Vec2>
		void check(span<const block> inputs, Vec values, Vec2 output)
		{
			auto h = values.defaultHelper();
			auto v2 = h.newVec(values.size());
			decode(inputs, v2, output, h, 1);

			for (u64 i = 0; i < values.size(); ++i)
			{
				if (h.eq(v2[i],values[i]) == false)
				{
					std::cout << "paxos failed to encode. \n"
						<< "inputs[" << i << "]" << inputs[i] << "\n"
						<< "seed " << mSeed << "\n"
						<< "n " << size() << "\n"
						<< "m " << inputs.size() << "\n"
						<< std::endl;
					throw RTE_LOC;
				}
			}
		}

	};

	// invert a gf128 matrix.
	// 反转gf128矩阵。
	Matrix<block> gf128Inv(Matrix<block> mtx);

	// multiply two gf128 matrices.
	// 乘以两个gf128矩阵。
	Matrix<block> gf128Mul(const Matrix<block>& m0, const Matrix<block>& m1);

	template<typename IdxType>
	std::ostream& operator<<(std::ostream& o, const Paxos<IdxType>& p);
	//template<typename IdxType>
	//std::ostream& operator<<(std::ostream& o, const PaxosDiff<IdxType>& s);

}

// Since paxos is a template, we include the impl file.
#ifndef NO_INCLUDE_PAXOS_IMPL
#include "PaxosImpl.h"
#endif // !NO_INCLUDE_PAXOS_IMPL

