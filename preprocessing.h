#ifndef PREPROCESSING_H
#define PREPROCESSING_H

extern std::vector<std::vector<float>> Read_Iris_Dataset(void);
std::vector<std::vector<float>> split_by_class( std::vector<std::vector<float>> &dataset ,float data_class );
std::vector<std::vector<float>> vector_Train_Split(const std::vector<std::vector<float>> &vect , float percent);
std::vector<std::vector<float>> vector_Test_Split(std::vector<std::vector<float>> &vect , float percent);
float Vect_match_Score (const std::vector<float> &labels, const std::vector<float> &predictions );
#endif
