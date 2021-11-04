
#!/usr/bin/env python
# coding: utf-8

#!pip install pandas
#!pip install scikit-learn
#!pip install matplotlib
#!pip install xlrd
import sys
import warnings
warnings.filterwarnings("ignore")
import tensorflow as tf
tf.logging.set_verbosity(tf.logging.ERROR)
import itertools
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import confusion_matrix,accuracy_score,recall_score,precision_score,f1_score
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from keras.layers import Input,Dropout,Dense
from keras.models import Model
from keras import regularizers
from keras.utils.data_utils import get_file
#get_ipython().run_line_magic('matplotlib', 'inline')
from sklearn.decomposition import PCA
from keras.layers import LSTM, RepeatVector, TimeDistributed, Activation, LeakyReLU
import keras
from keras.models import Sequential
from sklearn.metrics import accuracy_score
from sklearn import preprocessing
from sklearn import metrics 
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import label_binarize
from os import listdir
from os.path import isfile, join
import pickle
from keras.models import load_model
import shutil
import os
np.random.seed(75)

TrainMode = False
TestMode = False
if str(sys.argv[1]) == "TrainMode":
    TrainMode = True
elif str(sys.argv[1]) == "TestMode":
    TestMode = True
    
    
figCounter = 0
def saveFig(fig):
    global figCounter
    figCounter = figCounter + 1
    fig.savefig("../site_1/site_1/static/img/" + str(figCounter) + '.png')
    fig.clf()

def clearFolder(folderName):
    for filename in os.listdir(folderName):
        file_path = os.path.join(folderName, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))


if TrainMode == True:
    mypath = "myapp/TrainData/"
    clearFolder("../site_1/site_1/static/img/")
    clearFolder("myapp/SavedModels/")
if TestMode == True:
    mypath = "myapp/TestData/"
    clearFolder("../site_1/site_1/static/img/")
    
onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
for i in range(len(onlyfiles)):
    print("Reading File: " + onlyfiles[i], file=sys.stderr)
    if i == 0 :
        currentDF = pd.read_excel( mypath + onlyfiles[i], sheet_name=0 )
    else:
        newDF = pd.read_excel( mypath + onlyfiles[i], sheet_name=0 )
        currentDF = currentDF.append(newDF, ignore_index=True)

#xl = pd.ExcelFile("myapp/TrainData/24 statistical features-20090101.xls")
#df1 = xl.parse("20090101") # Sheet name

'''
xl = pd.ExcelFile("myapp/TrainData/24 statistical features-20090102.xls")
df2 = xl.parse("20090102") # Sheet name

xl = pd.ExcelFile("myapp/TrainData/\24 statistical features-20090103.xls")
df3 = xl.parse("20090103") # Sheet name

xl = pd.ExcelFile("Data\\24 statistical features-20090104.xls")
df4 = xl.parse("20090104") # Sheet name
'''

df = currentDF
#df = df1.append(df2, ignore_index=True)
#df = df.append(df3, ignore_index=True)
#df = df.append(df4, ignore_index=True)
#df.head()

#for col in df.columns: 
#    print(col) 

df['Label'].value_counts()

df.Label[df.Label == 1] = 0 # Normal
df.Label[df.Label == -1] = 1 # known Attack
df.Label[df.Label == -2] = 2  # unknown Attack 

df['Label'].value_counts()
fig = df['Label'].value_counts().plot(kind='bar', title ="Number of each Labels").get_figure()
saveFig(fig)

labels = 'Normal','known Attack', 'unknown Attack'
sizes = [(df.Label[df.Label == 0]).size, (df.Label[df.Label == 1]).size, (df.Label[df.Label == 2]).size]
fig1, ax1 = plt.subplots()
ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
        shadow=True, startangle=90)
ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
#plt.show()
plt.suptitle('Percent of each Labels', fontsize=20)
saveFig(plt)

#print("Num of DDOS Attack:")
#print(df.Flag[df.Flag == "RSTOS0"].size)
#print("Sum of All DDOS Attacks Duration:")
#print(sum(df.Duration[df.Flag == "RSTOS0"]))
#print("Max DDOS Attack Duration:")
#print(max(df.Duration[df.Flag == "RSTOS0"]))
#print("Min DDOS Attack Duration:")
#print(min(df.Duration[df.Flag == "RSTOS0"]))

tmpDF = df[df.Flag == "RSTOS0"]
fig = tmpDF.groupby("Destination IP Address")["Destination IP Address"].size().plot(kind='pie', title ="Number of DDOS Attack by Destination IP Address").get_figure() #  , figsize = (9,12)
saveFig(fig)

fig = tmpDF.groupby("Destination IP Address")["Duration"].sum().plot(kind='pie', title = "Duration of DDOS Attack by Destination IP Address").get_figure()
saveFig(fig)

fig = df[df.Label == 0].groupby("Flag")["Flag"].size().plot(kind='pie', autopct='%1.1f%%', title = "Flags for Normal Records").get_figure()
saveFig(fig)

fig = df[df.Label == 1].groupby("Flag")["Flag"].size().plot(kind='pie', autopct='%1.1f%%', title = "Flags for known Attack Records").get_figure()
saveFig(fig)

fig = df[df.Label == 2].groupby("Flag")["Flag"].size().plot(kind='pie',autopct='%1.1f%%', title = "Flags for unknown Records").get_figure()
saveFig(fig)

df['Ashula detection'].value_counts()
fig = df['Ashula detection'].value_counts().plot(kind='bar', title = "Ashula detection").get_figure()
saveFig(fig)

fig = df['Ashula detection'].value_counts().plot(kind='pie', title = "Ashula detection").get_figure()
saveFig(fig)

df['Malware detection'].value_counts()
fig = df['Malware detection'].value_counts().plot(kind='bar', title = "Malware detection").get_figure()
saveFig(fig)

fig = df['Malware detection'].value_counts().plot(kind='pie', title = "Malware detection").get_figure()
saveFig(fig)

df['IDS detection'].value_counts()
fig = df['IDS detection'].value_counts().plot(kind='bar', title = "IDS detection").get_figure()
saveFig(fig)

fig = df['IDS detection'].value_counts().plot(kind='pie', title = "IDS detection").get_figure()
saveFig(fig)

df = df.rename(columns={'Label': 'Class'})

df = df.rename(columns={'Unnamed: 24': 'protocol'})
del df['Duration.1'] 
del df['Start Time']

df["Source IP Address:"] = df["Source IP Address:"].astype('category')
df["Source IP Address:"] = df["Source IP Address:"].cat.codes

df["Destination IP Address"] = df["Destination IP Address"].astype('category')
df["Destination IP Address"] = df["Destination IP Address"].cat.codes


msk = np.random.rand(len(df)) < 0.5
training_df = df[msk]
testing_df = df[~msk]

#training_df.head()
#testing_df.head()
#print("Training set has {} rows.".format(len(training_df)))
#print("Testing set has {} rows.".format(len(testing_df)))

#https://datascience.stackexchange.com/questions/26886/valueerror-input-contains-nan-infinity-or-a-value-too-large-for-dtypefloat64
training_df = training_df.reset_index(drop=True)
testing_df = testing_df.reset_index(drop=True)
training_df =training_df[~training_df.isin([np.nan, np.inf, -np.inf]).any(1)]
testing_df =testing_df[~testing_df.isin([np.nan, np.inf, -np.inf]).any(1)]

#training_df.head()

def minmax_scale_values(training_df,testing_df, col_name):
    scaler = MinMaxScaler()
    #scaler = preprocessing.StandardScaler()
    scaler = scaler.fit(training_df[col_name].values.reshape(-1, 1))
    train_values_standardized = scaler.transform(training_df[col_name].values.reshape(-1, 1))
    training_df[col_name] = train_values_standardized
    test_values_standardized = scaler.transform(testing_df[col_name].values.reshape(-1, 1))
    testing_df[col_name] = test_values_standardized

def encode_text(training_df,testing_df, name):   
    training_set_dummies = pd.get_dummies(training_df[name])
    testing_set_dummies = pd.get_dummies(testing_df[name])
    for x in training_set_dummies.columns:
        dummy_name = "{}_{}".format(name, x)
        training_df[dummy_name] = training_set_dummies[x]
        if x in testing_set_dummies.columns :
            testing_df[dummy_name]=testing_set_dummies[x]
        else :
            testing_df[dummy_name]=np.zeros(len(testing_df))
            
    training_df.drop(name, axis=1, inplace=True)
    testing_df.drop(name, axis=1, inplace=True)

sympolic_columns=["protocol","Service","Flag","IDS detection","Malware detection","Ashula detection"]
ip_columns = ["Source IP Address:", "Destination IP Address"]
label_column="Class"
for column in df.columns :
    if column in label_column:
        continue
    if column in ip_columns:
        continue
    if column in sympolic_columns:
        encode_text(training_df,testing_df,column)
    else:
        minmax_scale_values(training_df,testing_df, column)
    

#training_df.head(5)
#testing_df.head(5)

#for col in training_df.columns: 
#    print(col) 

training_df.Class[training_df.Class == 2] = 1  # unknown Attack 
testing_df.Class[testing_df.Class == 2] = 1  # unknown Attack 
classes=[0, 1] #classes=[0, 1, 2]

x,y=training_df,training_df.pop("Class").values
x=x.values
x_test,y_test=testing_df,testing_df.pop("Class").values
x_test=x_test.values

fpr_dict = dict()
tpr_dict = dict()
roc_auc_dict = dict()

def drawROC(y_test, preds, classifierName, inputTitle):
    global result_table
    fpr, tpr, threshold = metrics.roc_curve(y_test, preds)
    roc_auc = metrics.auc(fpr, tpr)

    # method I: plt
    import matplotlib.pyplot as plt
    plt.title(inputTitle)
    plt.plot(fpr, tpr, 'b', label = 'AUC = %0.2f' % roc_auc)
    plt.legend(loc = 'lower right')
    plt.plot([0, 1], [0, 1],'r--')
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
    #plt.show()
    saveFig(plt)

    fpr_dict[len(fpr_dict)] = fpr
    tpr_dict[len(tpr_dict)] = tpr
    roc_auc_dict[len(roc_auc_dict)] = roc_auc
    
'''    
def drawROC_multiClass(y_test, preds, classifierName):
    #https://scikit-learn.org/stable/auto_examples/model_selection/plot_roc.html
    global result_table
    n_classes = 3
    # Compute ROC curve and ROC area for each class
    fpr = dict()
    tpr = dict()
    roc_auc = dict()
    for i in range(n_classes):
        fpr[i], tpr[i], _ = metrics.roc_curve(y_test[:, i], preds[:, i])
        roc_auc[i] = metrics.auc(fpr[i], tpr[i])

    # Compute micro-average ROC curve and ROC area
    fpr["micro"], tpr["micro"], _ = metrics.roc_curve(y_test.ravel(), preds.ravel())
    roc_auc["micro"] = metrics.auc(fpr["micro"], tpr["micro"])

    # Plot of a ROC curve for a specific class
    #plt.figure()
    #plt.plot(fpr[2], tpr[2], label='ROC curve (area = %0.2f)' % roc_auc[2])
    #plt.plot([0, 1], [0, 1], 'k--')
    #plt.xlim([0.0, 1.0])
    #plt.ylim([0.0, 1.05])
    #plt.xlabel('False Positive Rate')
    #plt.ylabel('True Positive Rate')
    #plt.title('Receiver operating characteristic example')
    #plt.legend(loc="lower right")
    #plt.show()

    # Plot ROC curve
    plt.figure()
    plt.plot(fpr["micro"], tpr["micro"],
             label='micro-average ROC curve (area = {0:0.2f})'
                   ''.format(roc_auc["micro"]))
    for i in range(n_classes):
        plt.plot(fpr[i], tpr[i], label='ROC curve of class {0} (area = {1:0.2f})'
                                       ''.format(i, roc_auc[i]))

    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Some extension of Receiver operating characteristic to multi-class')
    plt.legend(loc="lower right")
    #plt.show()
    saveFig(plt)
'''
 
def plot_confusion_matrix(cm, classes, inputTitle, normalize=False, cmap=plt.cm.Greys):
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(inputTitle)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)

    fmt = '.2f' if normalize else 'd'
    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, format(cm[i, j], fmt),
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")

    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    saveFig(plt)
    
'''
def plot_scatter(y_test, testing_set_predictions, inputTitle):
    import seaborn as sns
    import matplotlib.pyplot as plt
    #sns.set_theme(style="ticks", color_codes=True)
    #tips = sns.load_dataset("tips")
    #sns.catplot(x="day", y="total_bill",  hue="sex", data=tips)
    #add y_test and testing_set_predictions to testing_df
    tmpDF = testing_df
    tmpDF = pd.concat([tmpDF, pd.DataFrame(y_test)], axis=1)
    tmpDF.columns = [*tmpDF.columns[:-1], 'y_test']
    tmpDF = pd.concat([tmpDF, pd.DataFrame(testing_set_predictions)], axis=1)
    tmpDF.columns = [*tmpDF.columns[:-1], 'testing_set_predictions']
    tmpDF = tmpDF[tmpDF.Duration<0.2]
    #fig = sns.catplot(x="y_test", y="Duration",  hue="testing_set_predictions", kind="swarm", data=tmpDF).get_figure()#,jitter = 0.3
    #fig = sns.swarmplot(data=tmpDF, x="y_test", y="Duration", hue="testing_set_predictions")
    #sns_plot = sns.pairplot(x="y_test", y="Duration",  hue="testing_set_predictions", kind="swarm", data=tmpDF)
    #sns_plot.savefig("output.png")
    #saveFig(fig.figure)
'''   
    
def rand_jitter(arr):
    stdev = .03 * (max(arr) - min(arr))
    return arr + np.random.randn(len(arr)) * stdev


def plot_scatter(y_test, testing_set_predictions, inputTitle):
    import seaborn as sns
    import matplotlib.pyplot as plt
    #sns.set_theme(style="ticks", color_codes=True)
    #tips = sns.load_dataset("tips")
    #sns.catplot(x="day", y="total_bill",  hue="sex", data=tips)
    #add y_test and testing_set_predictions to testing_df
    tmpDF = testing_df
    tmpDF = pd.concat([tmpDF, pd.DataFrame(y_test)], axis=1)
    tmpDF.columns = [*tmpDF.columns[:-1], 'y_test']
    tmpDF = pd.concat([tmpDF, pd.DataFrame(testing_set_predictions)], axis=1)
    tmpDF.columns = [*tmpDF.columns[:-1], 'testing_set_predictions']
    tmpDF = tmpDF[tmpDF.Duration<0.2]
    #sns.catplot(x="y_test", y="Duration",  hue="testing_set_predictions", kind="swarm", data=tmpDF)#,jitter = 0.3
    #sns.swarmplot(data=tmpDF, x="y_test", y="Duration", hue="testing_set_predictions")
    plt.figure()
    plt.title(inputTitle)
    plt.ylabel('Duration')
    plt.xlabel('y_test')
    x=rand_jitter(tmpDF.y_test)
    y=rand_jitter(tmpDF.Duration)
    plt.scatter(rand_jitter(x), rand_jitter(y), c =tmpDF.testing_set_predictions )
    saveFig(plt)



All_Models = []
All_Accuracy = []
All_Recall = []
All_Precision = []
All_F1 = []

trainingSize = [0.01,0.02,0.03,0.04]

print("k-NN Running...", file=sys.stderr)

from sklearn.neighbors import KNeighborsClassifier
clf = OneVsRestClassifier(KNeighborsClassifier(n_neighbors=3))
#https://scikit-learn.org/stable/modules/generated/sklearn.tree.DecisionTreeClassifier.html

if TrainMode == True:
    clf.fit(x, y)
    pickle.dump(clf, open("myapp/SavedModels/KNN_Model", 'wb'))
if TestMode == True:    
    clf = pickle.load(open("myapp/SavedModels/KNN_Model", 'rb'))
    
testing_set_predictions = clf.predict(x_test)
accuracy=accuracy_score(y_test,testing_set_predictions)
recall=recall_score(y_test,testing_set_predictions, average = "micro")
#https://scikit-learn.org/stable/modules/generated/sklearn.metrics.recall_score.html
precision=precision_score(y_test,testing_set_predictions, average = "micro")
f1=f1_score(y_test,testing_set_predictions, average = "micro")
#print("Performance over the testing data set \n")
#print("Accuracy : {} , Recall : {} , Precision : {} , F1 : {}\n".format(accuracy,recall,precision,f1 ))
All_Models.append("KNeighborsClassifier")
All_Accuracy.append(accuracy)
All_Recall.append(recall)
All_Precision.append(precision)
All_F1.append(f1)
drawROC(y_test, testing_set_predictions, "KNeighborsClassifier", "KNN: ROC Plot")
c = confusion_matrix(y_test,testing_set_predictions)
plot_confusion_matrix(c,["0","1"], "KNN: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
plot_scatter(y_test, testing_set_predictions, "KNN: Scatter Plot")

improvmentArray_Tree = []
for i in range(len(trainingSize)):
    msk = np.random.rand(len(x)) < trainingSize[i]
    msk_x = x[msk]
    msk_y = y[msk]
    clf.fit(msk_x, msk_y)
    testing_set_predictions = clf.predict(x_test)
    accuracy=accuracy_score(y_test,testing_set_predictions)
    improvmentArray_Tree.append(accuracy)

'''
from sklearn.neighbors import KNeighborsClassifier

clf = OneVsRestClassifier(KNeighborsClassifier(n_neighbors=3))
#https://scikit-learn.org/stable/modules/generated/sklearn.tree.DecisionTreeClassifier.html

y_test_binary = label_binarize(y_test, classes=[0, 1, 2])
clf.fit(x, y)

testing_set_predictions = clf.predict(x_test)
testing_set_predictions_binary = label_binarize(testing_set_predictions, classes=[0, 1, 2])

accuracy=accuracy_score(y_test,testing_set_predictions)
recall=recall_score(y_test,testing_set_predictions, average = "micro")
#https://scikit-learn.org/stable/modules/generated/sklearn.metrics.recall_score.html
precision=precision_score(y_test,testing_set_predictions, average = "micro")
f1=f1_score(y_test,testing_set_predictions, average = "micro")
print("Performance over the testing data set \n")
print("Accuracy : {} , Recall : {} , Precision : {} , F1 : {}\n".format(accuracy,recall,precision,f1 ))
All_Models.append("KNeighborsClassifier")
All_Accuracy.append(accuracy)
All_Recall.append(recall)
All_Precision.append(precision)
All_F1.append(f1)
drawROC_multiClass(y_test_binary, testing_set_predictions_binary, "KNeighborsClassifier")
c = confusion_matrix(y_test,testing_set_predictions)
plot_confusion_matrix(c,["0","1","2"])

improvmentArray_Tree = []
for i in range(len(trainingSize)):
    msk = np.random.rand(len(x)) < trainingSize[i]
    msk_x = x[msk]
    msk_y = y[msk]
    clf.fit(msk_x, msk_y)
    testing_set_predictions = clf.predict(x_test)
    accuracy=accuracy_score(y_test,testing_set_predictions)
    improvmentArray_Tree.append(accuracy)
'''

print("Decision Tree Running...", file=sys.stderr)
from sklearn import tree
clf = tree.DecisionTreeClassifier(criterion ="gini", splitter ="best", max_depth = 3, min_samples_split = 2, min_samples_leaf = 2)
#https://scikit-learn.org/stable/modules/generated/sklearn.tree.DecisionTreeClassifier.html

if TrainMode == True:
    clf.fit(x, y)
    pickle.dump(clf, open("myapp/SavedModels/DT_Model", 'wb'))
if TestMode == True:    
    clf = pickle.load(open("myapp/SavedModels/DT_Model", 'rb'))
    
testing_set_predictions = clf.predict(x_test)
accuracy=accuracy_score(y_test,testing_set_predictions)
recall=recall_score(y_test,testing_set_predictions, average = "micro")
#https://scikit-learn.org/stable/modules/generated/sklearn.metrics.recall_score.html
precision=precision_score(y_test,testing_set_predictions, average = "micro")
f1=f1_score(y_test,testing_set_predictions, average = "micro")
#print("Performance over the testing data set \n")
#print("Accuracy : {} , Recall : {} , Precision : {} , F1 : {}\n".format(accuracy,recall,precision,f1 ))
All_Models.append("DecisionTree")
All_Accuracy.append(accuracy)
All_Recall.append(recall)
All_Precision.append(precision)
All_F1.append(f1)
#drawROC_multiClass(y_test_binary, testing_set_predictions_binary, "Tree")
drawROC(y_test, testing_set_predictions, "Decison Tree", "DecisionTree: ROC Plot")
c = confusion_matrix(y_test,testing_set_predictions)
plot_confusion_matrix(c,["0","1"], "DecisionTree: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
plot_scatter(y_test, testing_set_predictions, "DecisionTree: Scatter Plot")

improvmentArray_Tree = []
for i in range(len(trainingSize)):
    msk = np.random.rand(len(x)) < trainingSize[i]
    msk_x = x[msk]
    msk_y = y[msk]
    clf.fit(msk_x, msk_y)
    testing_set_predictions = clf.predict(x_test)
    accuracy=accuracy_score(y_test,testing_set_predictions)
    improvmentArray_Tree.append(accuracy)


print("RandomForest Running...", file=sys.stderr)
from sklearn.ensemble import RandomForestClassifier
clf = RandomForestClassifier(criterion ="gini", max_depth=5, min_samples_split = 2, random_state=0)
#https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html

if TrainMode == True:
    clf.fit(x, y)
    pickle.dump(clf, open("myapp/SavedModels/RF_Model", 'wb'))
if TestMode == True:    
    clf = pickle.load(open("myapp/SavedModels/RF_Model", 'rb'))
    
testing_set_predictions = clf.predict(x_test)
accuracy=accuracy_score(y_test,testing_set_predictions)
recall=recall_score(y_test,testing_set_predictions, average = "micro")
precision=precision_score(y_test,testing_set_predictions, average = "micro")
f1=f1_score(y_test,testing_set_predictions, average = "micro")
#print("Performance over the testing data set \n")
#print("Accuracy : {} , Recall : {} , Precision : {} , F1 : {}\n".format(accuracy,recall,precision,f1 ))
All_Models.append("RandomForest_1")
All_Accuracy.append(accuracy)
All_Recall.append(recall)
All_Precision.append(precision)
All_F1.append(f1)
drawROC(y_test, testing_set_predictions, "RT Forest_1", "RandomForest: ROC Plot")
c = confusion_matrix(y_test,testing_set_predictions)
plot_confusion_matrix(c,["0","1"], "RandomForest: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
plot_scatter(y_test, testing_set_predictions, "RandomForest: Scatter Plot")

improvmentArray_RandomForest_1 = []
for i in range(len(trainingSize)):
    msk = np.random.rand(len(x)) < trainingSize[i]
    msk_x = x[msk]
    msk_y = y[msk]
    clf.fit(msk_x, msk_y)
    testing_set_predictions = clf.predict(x_test)
    accuracy=accuracy_score(y_test,testing_set_predictions)
    improvmentArray_RandomForest_1.append(accuracy)


print("MLP Running...", file=sys.stderr)
from sklearn.neural_network import MLPClassifier
clf = MLPClassifier(hidden_layer_sizes = (10,), solver = "adam", learning_rate = "constant" , random_state=1, max_iter=20)
#https://scikit-learn.org/stable/modules/generated/sklearn.neural_network.MLPClassifier.html

if TrainMode == True:
    clf.fit(x, y)
    pickle.dump(clf, open("myapp/SavedModels/MLP_Model", 'wb'))
if TestMode == True:    
    clf = pickle.load(open("myapp/SavedModels/MLP_Model", 'rb'))
    
testing_set_predictions = clf.predict(x_test)
accuracy=accuracy_score(y_test,testing_set_predictions)
recall=recall_score(y_test,testing_set_predictions, average = "micro")
precision=precision_score(y_test,testing_set_predictions, average = "micro")
f1=f1_score(y_test,testing_set_predictions, average = "micro")
#print("Performance over the testing data set \n")
#print("Accuracy : {} , Recall : {} , Precision : {} , F1 : {}\n".format(accuracy,recall,precision,f1 ))
All_Models.append("MLP")
All_Accuracy.append(accuracy)
All_Recall.append(recall)
All_Precision.append(precision)
All_F1.append(f1)
drawROC(y_test, testing_set_predictions, "MLP", "MLP: ROC Plot")
c = confusion_matrix(y_test,testing_set_predictions)
plot_confusion_matrix(c,["0","1"], "MLP: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
plot_scatter(y_test, testing_set_predictions, "MLP: Scatter Plot")

improvmentArray_MLP = []
for i in range(len(trainingSize)):
    msk = np.random.rand(len(x)) < trainingSize[i]
    msk_x = x[msk]
    msk_y = y[msk]
    clf.fit(msk_x, msk_y)
    testing_set_predictions = clf.predict(x_test)
    accuracy=accuracy_score(y_test,testing_set_predictions)
    improvmentArray_MLP.append(accuracy)


if TrainMode == True:
    print("PCA Running...", file=sys.stderr)
    from sklearn.decomposition import PCA
    pca = PCA(n_components=5)
    x_pca = pca.fit_transform(x)
    x_pca_test = pca.fit_transform(x_test)

    #n = 1000
    #mask = np.hstack([np.random.choice(np.where(y == l)[0], n, replace=False)
    #                      for l in np.unique(y)])

    #sampled_x = x[mask]
    #sampled_y = y[mask]

    def normalize(values, bounds):
        return [bounds['desired']['lower'] + (x - bounds['actual']['lower']) * (bounds['desired']['upper'] - bounds['desired']['lower']) / (bounds['actual']['upper'] - bounds['actual']['lower']) for x in values]


    print("SVM Running...", file=sys.stderr)
    #from sklearn.svm import SVC
    from sklearn.svm import LinearSVR
    #clf = SVC(kernel = "linear")
    #https://scikit-learn.org/stable/modules/generated/sklearn.svm.SVC.html
    #clf.fit(sampled_x, sampled_y)
    clf = LinearSVR(random_state=0, tol=1e-5)
    #https://scikit-learn.org/stable/modules/generated/sklearn.svm.LinearSVR.html
    clf.fit(x_pca, y)
    testing_set_predictions = clf.predict(x_pca_test)
    testing_set_predictions = normalize(
        testing_set_predictions,
        {'actual': {'lower': min(testing_set_predictions), 'upper': max(testing_set_predictions)}, 'desired': {'lower': -0.5, 'upper': 2.5}}
    ) 
    testing_set_predictions =[round(x, 0) for x in testing_set_predictions] 

    accuracy=accuracy_score(y_test,testing_set_predictions)
    recall=recall_score(y_test,testing_set_predictions, average = "micro")
    precision=precision_score(y_test,testing_set_predictions, average = "micro")
    f1=f1_score(y_test,testing_set_predictions, average = "micro")
    #print("Performance over the testing data set \n")
    #print("Accuracy : {} , Recall : {} , Precision : {} , F1 : {}\n".format(accuracy,recall,precision,f1 ))
    All_Models.append("SVM")
    All_Accuracy.append(accuracy)
    All_Recall.append(recall)
    All_Precision.append(precision)
    All_F1.append(f1)
    drawROC(y_test, testing_set_predictions, "SVM", "SVM: ROC Plot")
    c = confusion_matrix(y_test,testing_set_predictions)
    plot_confusion_matrix(c,["0","1"], "SVM: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
    plot_scatter(y_test, testing_set_predictions, "SVM: Scatter Plot")

    improvmentArray_SVC = []
    for i in range(len(trainingSize)):
        #msk = np.random.rand(len(sampled_x)) < trainingSize[i]
        #msk_sampled_x= sampled_x[msk]
        #msk_sampled_y = sampled_y[msk]
        clf.fit(x_pca, y)
        testing_set_predictions = clf.predict(x_pca_test)
        
        testing_set_predictions = normalize(
        testing_set_predictions,
        {'actual': {'lower': min(testing_set_predictions), 'upper': max(testing_set_predictions)}, 'desired': {'lower': -0.5, 'upper': 2.5}}
        ) 
        testing_set_predictions =[round(x, 0) for x in testing_set_predictions] 
        accuracy=accuracy_score(y_test,testing_set_predictions)
        improvmentArray_SVC.append(accuracy)


print("KMeans Running...", file=sys.stderr)
from sklearn.cluster import KMeans
clf = KMeans(n_clusters=2, random_state=0)
#https://scikit-learn.org/stable/modules/generated/sklearn.cluster.KMeans.html

if TrainMode == True:
    clf.fit(x, y)
    pickle.dump(clf, open("myapp/SavedModels/KMeans_Model", 'wb'))
if TestMode == True:    
    clf = pickle.load(open("myapp/SavedModels/KMeans_Model", 'rb'))
    
testing_set_predictions = clf.predict(x_test)
accuracy=accuracy_score(y_test,testing_set_predictions)
recall=recall_score(y_test,testing_set_predictions, average = "micro")
precision=precision_score(y_test,testing_set_predictions, average = "micro")
f1=f1_score(y_test,testing_set_predictions, average = "micro")
#print("Performance over the testing data set \n")
#print("Accuracy : {} , Recall : {} , Precision : {} , F1 : {}\n".format(accuracy,recall,precision,f1 ))
All_Models.append("kMeans")
All_Accuracy.append(accuracy)
All_Recall.append(recall)
All_Precision.append(precision)
All_F1.append(f1)
drawROC(y_test, testing_set_predictions, "kMeans", "KMeans: ROC Plot")
c = confusion_matrix(y_test,testing_set_predictions)
plot_confusion_matrix(c,["0","1"], "KMeans: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
plot_scatter(y_test, testing_set_predictions, "KMeans: Scatter Plot")

improvmentArray_kMeans = []
for i in range(len(trainingSize)):
    msk = np.random.rand(len(x)) < trainingSize[i]
    msk_x= x[msk]
    msk_y = y[msk]
    clf.fit(msk_x, msk_y)
    testing_set_predictions = clf.predict(x_test)
    accuracy=accuracy_score(y_test,testing_set_predictions)
    improvmentArray_kMeans.append(accuracy)

#if TrainMode == True:

    
print("Dense Running...", file=sys.stderr)
#print(x.shape)
y_dense = keras.utils.to_categorical(y, len(classes))
y_dense_test = keras.utils.to_categorical(y_test, len(classes))

from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
#Buildling and training the model
def get_Dense_Model():
    n_features = x.shape[1]
    model = Sequential()
    model.add(Dense(12, input_dim=n_features, activation='relu'))
    model.add(Dense(8, activation='relu'))
    model.add(Dense(2, activation='softmax'))
    return model


if TrainMode == True:
    denseModel=get_Dense_Model()
    #denseModel.summary()
    denseModel.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    denseModel.fit(x, y_dense, epochs=10, batch_size=20, verbose = 0)
    #denseModel.save("myapp/SavedModels/DENSE_Model.h5")
    denseModel.save_weights("myapp/SavedModels/DENSE_Model")

#if TestMode == True:    
#    #denseModel = load_model("myapp/SavedModels/DENSE_Model.h5")
#    denseModel.load_weights("myapp/SavedModels/DENSE_Model")
        
    _, accuracy = denseModel.evaluate(x_test, y_dense_test)
    #print('Accuracy: %.2f' % (accuracy*100))
    All_Models.append("Dense Model")
    All_Accuracy.append(accuracy)
    testing_set_predictions = denseModel.predict_classes(x_test)
    drawROC(y_test, testing_set_predictions, "Dense", "Dense: ROC Plot")
    c = confusion_matrix(y_test,testing_set_predictions)
    plot_confusion_matrix(c,["0","1"], "Dense: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
    All_Recall.append(recall_score(y_test,testing_set_predictions, average = "micro"))
    All_Precision.append(precision_score(y_test,testing_set_predictions, average = "micro"))
    All_F1.append(f1_score(y_test,testing_set_predictions, average = "micro"))

    improvmentArray_DENSE = []
    for i in range(len(trainingSize)):
        msk = np.random.rand(len(x)) < trainingSize[i]
        msk_x = x[msk]
        msk_y_dense = y_dense[msk]
        denseModel.fit(msk_x, msk_y_dense, epochs=10, batch_size=20, verbose = 0)
        _, accuracy = denseModel.evaluate(x_test, y_dense_test)
        improvmentArray_DENSE.append(accuracy)


print("CNN1D Running...", file=sys.stderr)
from keras.layers import Convolution1D,MaxPooling1D, Flatten
#Buildling and training the model
def get_CNN1D_Model():
    n_features = x.shape[1]
    cnn_network = Sequential()
    cnn_network.add(Convolution1D(64, 3,activation="relu",input_shape=(n_features, 1)))
    cnn_network.add(Convolution1D(64, 3, activation="relu"))
    #cnn_network.add(MaxPooling1D(pool_length=(2)))
    #cnn_network.add(Convolution1D(128, 3, activation="relu"))
    #cnn_network.add(Convolution1D(128, 3, activation="relu"))
    #cnn_network.add(MaxPooling1D(pool_length=(2)))
    cnn_network.add(Flatten())
    #cnn_network.add(Dense(128, activation="relu"))
    #cnn_network.add(Dropout(0.5))
    cnn_network.add(Dense(2, activation="softmax"))# linear, sigmoid
    return cnn_network


if TrainMode == True:
    CNN1D_Model=get_CNN1D_Model()
    CNN1D_Model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    new_x = np.reshape(x, (x.shape[0],x.shape[1],1))
    CNN1D_Model.fit(new_x, y_dense, epochs=2, batch_size=20, verbose = 0)
    CNN1D_Model.save("myapp/SavedModels/CNN1D_Model.h5")

#if TestMode == True:    
#    CNN1D_Model = load_model("myapp/SavedModels/CNN1D_Model.h5")
    
    
    new_x_test = np.reshape(x_test, (x_test.shape[0], x_test.shape[1],1))
    _, accuracy = CNN1D_Model.evaluate(new_x_test, y_dense_test)
    #print('Accuracy: %.2f' % (accuracy*100))
    All_Models.append("CNN1D Model")
    All_Accuracy.append(accuracy)
    testing_set_predictions = CNN1D_Model.predict_classes(new_x_test)
    drawROC(y_test, testing_set_predictions, "CNN1D", "CNN1D: ROC Plot")
    c = confusion_matrix(y_test,testing_set_predictions)
    plot_confusion_matrix(c,["0","1"], "CNN1D: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
    plot_scatter(y_test, testing_set_predictions, "CNN1D: Scatter Plot")
    All_Recall.append(recall_score(y_test,testing_set_predictions, average = "micro"))
    All_Precision.append(precision_score(y_test,testing_set_predictions, average = "micro"))
    All_F1.append(f1_score(y_test,testing_set_predictions, average = "micro"))

    improvmentArray_CNN1D = []
    for i in range(len(trainingSize)):
        msk = np.random.rand(len(x)) < trainingSize[i]
        msk_new_x = new_x[msk]
        msk_y_dense = y_dense[msk]
        CNN1D_Model.fit(msk_new_x, msk_y_dense, epochs=2, batch_size=20, verbose = 0)
        _, accuracy = CNN1D_Model.evaluate(new_x_test, y_dense_test)
        improvmentArray_CNN1D.append(accuracy)



print("Autoencoder LSTM Running...", file=sys.stderr)
#Autoencoder LSTM
x = np.expand_dims(x, axis=1)
#print(x.shape)
# NOTES:
# About RepeatVector: the RepeatVector layer repeats the incoming inputs a specific number of time. Consider below example:
# model.add(Dense(32, input_dim=32))
# model.add(RepeatVector(3))
# The shape of the input in the above example was ( 32 , ). But the output shape of the RepeatVector was ( 3 , 32 ), since the inputs were repeated 3 times.
# Use of LSTM: keras.layers.LSTM(units, activation='tanh', recurrent_activation='sigmoid', use_bias=True, kernel_initializer='glorot_uniform', recurrent_initializer='orthogonal', bias_initializer='zeros', unit_forget_bias=True, kernel_regularizer=None, recurrent_regularizer=None, bias_regularizer=None, activity_regularizer=None, kernel_constraint=None, recurrent_constraint=None, bias_constraint=None, dropout=0.0, recurrent_dropout=0.0, implementation=2, return_sequences=False, return_state=False, go_backwards=False, stateful=False, unroll=False)
#Buildling and training the model
def get_LSTM_Model():
    #http://mehrdadsalimi.blog.ir/1396/02/25/Understanding-LSTM-Networks
    timesteps = 1
    n_features = x.shape[2]

    '''
    model = Sequential()
    model.add(LSTM(4, activation='relu', input_shape=(timesteps,n_features), return_sequences=True))
    model.add(LSTM(2, activation='relu', return_sequences=False))
    model.add(RepeatVector(timesteps))
    model.add(LSTM(2, activation='relu', return_sequences=True))
    model.add(LSTM(4, activation='relu', return_sequences=True))
    model.add(TimeDistributed(Dense(n_features)))
    model.compile(optimizer='adam', loss='mse')
    '''
    
    
    model = Sequential()
    model.add(LSTM(1, activation='sigmoid', input_shape=(timesteps,n_features), return_sequences=False))
    model.add(RepeatVector(timesteps))
    model.add(LSTM(1, activation='sigmoid', return_sequences=True))
    model.add(TimeDistributed(Dense(n_features)))
    model.compile(optimizer='adam', loss='mse')
    
    '''
    model = Sequential()
    model.add(LSTM(128, activation='relu', input_shape=(timesteps,n_features), return_sequences=True))
    model.add(LSTM(64, activation='relu', return_sequences=False))
    model.add(RepeatVector(timesteps))
    model.add(LSTM(64, activation='relu', return_sequences=True))
    model.add(LSTM(128, activation='relu', return_sequences=True))
    model.add(LSTM(128, activation='relu', input_shape=(timesteps,n_features), return_sequences=True))
    model.add(LSTM(64, activation='relu', return_sequences=False))
    model.add(RepeatVector(timesteps))
    model.add(LSTM(64, activation='relu', return_sequences=True))
    model.add(LSTM(128, activation='relu', return_sequences=True))
    model.add(TimeDistributed(Dense(n_features)))
    model.compile(optimizer='adam', loss='mse')
    '''
    return model


if TrainMode == True:
    autoencoder=get_LSTM_Model()
    history=autoencoder.fit(x[np.where(y==1)],x[np.where(y==1)],epochs=10,batch_size=20,shuffle=True,validation_split=0.2, verbose = 0)
    # We set the threshold equal to the training loss of the autoencoder
    threshold=history.history["loss"][-1]
    fpHnd = open("myapp/SavedModels/threshold.txt","w") 
    fpHnd.write(str(threshold))
    fpHnd.close()
    autoencoder.save("myapp/SavedModels/autoencoder.h5")

#if TestMode == True:    
#    autoencoder = load_model("myapp/SavedModels/autoencoder.h5")
#    fpHnd = open("myapp/SavedModels/threshold.txt","r") 
#    threshold = fpHnd.readline() 
#    threshold = float(threshold)
#    fpHnd.close()


    x_test = np.expand_dims(x_test, axis=1)
    #function that calculates the reconstruction loss of each data sample
    def calculate_losses(x,preds):
        losses=np.zeros(len(x))
        for i in range(len(x)):
            losses[i]=((preds[i] - x[i]) ** 2).mean(axis=None)
            
        return losses


    testing_set_predictions=autoencoder.predict(x_test)
    test_losses=calculate_losses(x_test,testing_set_predictions)
    testing_set_predictions=np.zeros(len(test_losses))
    testing_set_predictions[np.where(test_losses>threshold)]=1
    accuracy=accuracy_score(y_test,testing_set_predictions)
    recall=recall_score(y_test,testing_set_predictions, average = "micro")
    precision=precision_score(y_test,testing_set_predictions, average = "micro")
    f1=f1_score(y_test,testing_set_predictions, average = "micro")
    print("Performance over the testing data set \n")
    print("Accuracy : {} , Recall : {} , Precision : {} , F1 : {}\n".format(accuracy,recall,precision,f1))
    drawROC(y_test, testing_set_predictions, "Autoencoder LSTM", "Autoencoder LSTM: ROC Plot")
    c = confusion_matrix(y_test,testing_set_predictions)
    plot_confusion_matrix(c,["0","1"], "Autoencoder LSTM: Confusion Plot") #plot_confusion_matrix(c,["0","1","2"])
    plot_scatter(y_test, testing_set_predictions, "Autoencoder LSTM: Scatter Plot")

    All_Models.append("AutoEncoder LSTM Model")
    All_Accuracy.append(accuracy)
    All_Recall.append(recall)
    All_Precision.append(precision)
    All_F1.append(f1)

    improvmentArray_LSTM = []
    for i in range(len(trainingSize)):
        msk = np.random.rand(len(x)) < trainingSize[i]
        msk_x = x[msk]
        msk_y = y[msk]

        history=autoencoder.fit(msk_x[np.where(msk_y==1)],msk_x[np.where(msk_y==1)],epochs=10,batch_size=20,shuffle=True,validation_split=0.2, verbose = 0)

        threshold=history.history["loss"][-1]
        testing_set_predictions=autoencoder.predict(x_test)
        test_losses=calculate_losses(x_test,testing_set_predictions)
        testing_set_predictions=np.zeros(len(test_losses))
        testing_set_predictions[np.where(test_losses>threshold)]=1
        accuracy=accuracy_score(y_test,testing_set_predictions)
        improvmentArray_LSTM.append(accuracy)



index = np.arange(len(All_Models))
plt.figure() #figsize=(9,12)
plt.bar(index, All_Accuracy)
plt.xlabel('Class', fontsize=10)
plt.ylabel('Value', fontsize=10)
plt.xticks(index, All_Models, fontsize=10, rotation=30)
plt.title('Plot for Accuracy comparison')
#plt.show()
saveFig(plt)

#All_Models

labels = All_Models
sizes = All_Accuracy
fig1, ax1 = plt.subplots()
ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
        shadow=True, startangle=90)
ax1.axis('equal')
#plt.show()
saveFig(plt)

index = np.arange(len(All_Models))
plt.figure()
plt.bar(index, All_Recall)
plt.xlabel('Class', fontsize=10)
plt.ylabel('Value', fontsize=10)
plt.xticks(index, All_Models, fontsize=10, rotation=30)
plt.title('Plot for Recall comparison')
#plt.show()
saveFig(plt)

labels = All_Models
sizes = All_Recall
fig1, ax1 = plt.subplots()
ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
        shadow=True, startangle=90)
ax1.axis('equal')
#plt.show()
saveFig(plt)


index = np.arange(len(All_Models))
plt.figure()
plt.bar(index, All_Precision)
plt.xlabel('Class', fontsize=10)
plt.ylabel('Value', fontsize=10)
plt.xticks(index, All_Models, fontsize=10, rotation=30)
plt.title('Plot for Precision comparison')
#plt.show()
saveFig(plt)

labels = All_Models
sizes = All_Precision
fig1, ax1 = plt.subplots()
ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
        shadow=True, startangle=90)
ax1.axis('equal')
#plt.show()
saveFig(plt)


index = np.arange(len(All_Models))
plt.figure()
plt.bar(index, All_F1)
plt.xlabel('Class', fontsize=10)
plt.ylabel('Value', fontsize=10)
plt.xticks(index, All_Models, fontsize=10, rotation=30)
plt.title('Plot for F1 comparison')
#plt.show()
saveFig(plt)

labels = All_Models
sizes = All_F1
fig1, ax1 = plt.subplots()
ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
        shadow=True, startangle=90)
ax1.axis('equal')

#plt.show()
saveFig(plt)


'''
colors = ['blue', 'red', 'green', 'yellow', 'violet','black','purple']
for i, color in zip(range(len(All_Models)), colors):
    plt.plot(fpr_dict[i], tpr_dict[i], color=color,
             label='ROC curve of class {0} (area = {1:0.2f})'
             ''.format(i+1, roc_auc_dict[i]))
plt.plot([0, 1], [0, 1], 'k--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver operating characteristic for multi-class data')
plt.legend(loc="lower right")
plt.show()
'''


plt.plot(trainingSize, improvmentArray_Tree, color='blue', label='Tree')
plt.plot(trainingSize, improvmentArray_RandomForest_1, color='red', label='RandomForest_1')
plt.plot(trainingSize, improvmentArray_MLP, color='yellow', label='MLP')
plt.plot(trainingSize, improvmentArray_kMeans, color='violet', label='kMeans')
if TrainMode == True:
    plt.plot(trainingSize, improvmentArray_SVC, color='violet', label='SVC')
    plt.plot(trainingSize, improvmentArray_DENSE, color='black', label='DENSE')
    plt.plot(trainingSize, improvmentArray_CNN1D, color='black', label='CNN1D')
    plt.plot(trainingSize, improvmentArray_LSTM, color='purple', label='LSTM')
plt.xlabel('Training size')
plt.ylabel('Accuracy')
plt.title('Accuracy Comparison')
plt.legend(loc="lower right")
saveFig(plt)
#plt.show()
    
