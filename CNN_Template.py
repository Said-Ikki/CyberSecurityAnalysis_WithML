# -*- coding: utf-8 -*-

import os
import numpy as np # linear algebra

from sklearn.utils import shuffle

import tensorflow as tf
from tensorflow import keras
from keras import layers 
from keras.layers import Conv2D, MaxPooling2D
from tensorflow.keras.models import Sequential

from tensorflow.keras.preprocessing.image import img_to_array
from tensorflow.keras.utils import load_img

import pandas as pd
tf.random.set_seed(333) # adds a little randomness but the same randomness for debugging


# these 4 functions are useful for turning lots of images into useful data
# particularily, the first 3 make a dataframe for ez testing metrics, the 4th actually preprocesses
def genImageList(l): # cleans images
    return list( filter( lambda i: i.split(".")[-1] in ["png","jpg","jpeg"], l ) )
# filter ( function, input ), if the input matches the function requirements, add to list
# function takes the path, splits it across the '.' and places it in list if the last element[-1] has one of the three file extensions
# input = picture path

def genDf(images,labels):
    # creates data frame, holds the data and their label (mask on or off)
    df= pd.DataFrame(images,columns=["Image"]) # creates it, first column has image directory under column name Image
    df["Class"] = labels # second column holds a zero or one, yes or no mask
    return df

def genData(path): # takes a path
    # looks for the pictures in these paths
    MaskPath = r''+path+'/with_mask/'
    NoMaskPath = r''+path+'/without_mask/'

    MaskImages = genImageList( [ MaskPath+i for i in os.listdir(MaskPath) ] ) # make image list for every mask photo in directory
    # path + ( the name of every file in this path )
    MaskLabels = np.zeros(len(MaskImages)) # make the lable for the masks, wearing one means youre close to 0

    NoMaskImages = genImageList([NoMaskPath+i for i in os.listdir(NoMaskPath)])
    NoMaskLabels = np.ones(len(NoMaskImages)) # label for not wearing, close to 1 if you are

    # create dataframes
    MaskDf = genDf(MaskImages,MaskLabels) 
    NoMaskDf = genDf(NoMaskImages,NoMaskLabels) 

    # rrrandomize the dataframe contents, for training
    Df = pd.DataFrame(shuffle(pd.concat([MaskDf,NoMaskDf])),columns=MaskDf.columns)
    return Df


def processData(df): # takes in dataframe
    x,y = df["Image"],df["Class"] # and stores it into independent variables
    data = [] # holds all the image-into-useable-info stuff
    size = 100 # size of the picture
    for img_path in x: # every item in the dataframe needs to go through this
        image = load_img(img_path, target_size=(size, size)) # load that image
        image = img_to_array(image) # turn it into an array so it can be proccessed by AI
        image = image/255 # grayscale
        data.append(image) # tack it onto the data

    data = np.array(data, dtype="float32") # 'pixels' have floats in them cuz of the grayscaling, so the data type of the big images array needs to have floating points
    labels = np.array(y).reshape([-1,1]) # turn the labels into a column array
    return data,labels

# this creates the model
def createModel(shape=(100,100,3)): # takes image/shape sizeSpecs
    # 100x100 RBG ( 3 channels )    

    tf.random.set_seed(3333) # little bit of random but controlled
    
    model = Sequential() # build a sequential model, each layer moves to the next one (sequentially)
    
    #Convolution Layer
    model.add(layers.Conv2D(32, (3, 3), activation='relu', input_shape=shape)) # first convolution layer
        # 32 different filters, each 3x3
        # each neuron takes a 3x3 from the input, dot products with 3x3 filter
        # and places it in the feature map (output) relative to the [0][0] location on 3x3
        # activation function is relu, adds non linearity to the output for randomness
        # relu turns all negative numbers to 0
    # 
    model.add(layers.MaxPooling2D((2, 2))) # overy 2x2 square (no overlap) is shrunk into 1 square with the highest value in it
    
    #Convolution Layer
    model.add(layers.Conv2D(64, (3, 3), activation='relu'))
    model.add(layers.MaxPooling2D((2, 2)))
    
    model.add(layers.Conv2D(64, (3, 3), activation='relu'))
    
    #Flatten Layer
    model.add(layers.Flatten()) # turn the matrix into a linear vector 
    # so the Dense layers can work wonders
    
    model.add(layers.Dropout(0.2)) # kill off 20% of nodes to reduce overfitting
    
    #Dense Layer
    model.add(layers.Dense(64, activation='relu'))
    # old fashioned NN, uses relu and has 64 outputs
    
    model.add(layers.Dropout(0.2))
    
    #Output Layer : Binary Classification
    model.add(layers.Dense(1, activation='sigmoid'))
    # turns the outputs from the previous layer to 1 output
    # sigmoid turns the one output into a scale between 1 and 0: the guess
    
    model.compile(optimizer='adam',
                  loss = 'binary_crossentropy',
                  metrics=[tf.keras.metrics.Recall(),tf.keras.metrics.Precision(),tf.keras.metrics.AUC(
        num_thresholds=200, curve='ROC',
        summation_method='interpolation', name=None, dtype=None,
        thresholds=None, multi_label=False, label_weights=None
    ),'accuracy'])
    # loss function = binary crossentropy
    # optimizer = adam, an optimized gradient descent
    # bunch of metrics to see how we are doing
    return model


# now we use these functions to do stuff

# train the model
trainDataDF = genData("Dataset/Dataset")  # turn the images to data
trainx,trainy = processData(trainDataDF) # preproccess the data
baseModel = createModel() # create the model
baseModel.fit(trainx,trainy,epochs=20,verbose=1,validation_split=0.2) # and train it
# data includes: 
    # data
    # labels, 
    # epochs, number of times to run the program
    # verbose, shows all the cool info about how the epochs are going
    # validation splits, for testing to see how well the program actually works

# test it against something
testDF = genData("Dataset/TestOneImage")
testx,testy = processData(testDF)
'''
image = load_img( "Dataset/TestOneImage" , target_size=(100, 100)) # load that image
image = img_to_array(image) # turn it into an array so it can be proccessed by AI
image = tf.expand_dims(image, axis=0) # it usually expects multiple images, so give it another dimension to satisfy shape conditions
image = image/255 # grayscale
'''
baseModel.predict( testx )
# this asks if someone is *not* wearing a mask
# high value equals high certainty they are not wearing a mask
# low value equals low certainty of *not* wearing a mask (they are likely wearing a mask)

# save model to be used elsewhere
baseModel.save("V2")
#modelledWithoutTraining = keras.models.load_model("PortableModel")
#modelledWithoutTraining.predict( testx )